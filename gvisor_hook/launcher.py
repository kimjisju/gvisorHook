from __future__ import annotations

import argparse
import ipaddress
import json
import fcntl
import os
import select
import shutil
import signal
import socket
import struct
import subprocess
import sys
import shlex
import tempfile
import termios
import time
import tty
from contextlib import suppress
from pathlib import Path

from .bundle import DATASET_PLAN_INSTRUCTIONS, write_bundle_config
from .dataset import (
    DatasetSessionPaths,
    append_ndjson,
    create_dataset_session,
    default_dataset_root,
    make_session_id,
    record_terminal_chunk,
    utc_now,
)

def _apply_winsize(master_fd: int, *, cols: int, rows: int) -> None:
    # TIOCSWINSZ expects (rows, cols, xpixel, ypixel) as unsigned short.
    buf = struct.pack("HHHH", rows, cols, 0, 0)
    fcntl.ioctl(master_fd, termios.TIOCSWINSZ, buf)


def sync_pty_winsize(master_fd: int) -> None:
    try:
        size = shutil.get_terminal_size(fallback=(120, 40))
        cols = max(1, int(getattr(size, "columns", 120)))
        rows = max(1, int(getattr(size, "lines", 40)))
    except Exception:
        cols, rows = 120, 40
    with suppress(Exception):
        _apply_winsize(master_fd, cols=cols, rows=rows)


class ConsoleSocketServer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.server.bind(str(self.path))
        self.server.listen(1)

    def close(self) -> None:
        with suppress(Exception):
            self.server.close()
        with suppress(FileNotFoundError):
            self.path.unlink()

    def accept_master_fd(self, timeout: float) -> int:
        self.server.settimeout(timeout)
        conn, _ = self.server.accept()
        with conn:
            _, ancillary, *_ = conn.recvmsg(1, socket.CMSG_LEN(struct.calcsize("i")))
            for cmsg_level, cmsg_type, cmsg_data in ancillary:
                if cmsg_level == socket.SOL_SOCKET and cmsg_type == socket.SCM_RIGHTS:
                    return struct.unpack("i", cmsg_data[: struct.calcsize("i")])[0]
        raise RuntimeError("console socket did not receive a PTY file descriptor")

    def accept_master_fd_until_process_exit(
        self, timeout: float, child: subprocess.Popen[bytes]
    ) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline:
            remaining = max(0.1, min(1.0, deadline - time.time()))
            self.server.settimeout(remaining)
            try:
                return self.accept_master_fd(timeout=remaining)
            except socket.timeout:
                if child.poll() is not None:
                    raise RuntimeError(
                        f"runsc exited before console attachment (exit {child.returncode})"
                    )
        raise TimeoutError("timed out waiting for runsc console socket")


def find_runsc_binary() -> Path:
    repo_root = Path(__file__).resolve().parent.parent
    candidates = [
        repo_root / "third_party" / "gvisor" / "bin" / "runsc-hook",
        repo_root / "third_party" / "gvisor" / "bazel-bin" / "runsc" / "runsc_" / "runsc",
        Path("/home/kimjisu/gvisorHook/third_party/gvisor/bin/runsc-hook"),
        Path("/home/kimjisu/gvisorHook/third_party/gvisor/bazel-bin/runsc/runsc_/runsc"),
        Path(shutil.which("runsc") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find a custom runsc binary. Build it first with scripts/build_runsc.sh.")


def find_mitmdump_binary() -> Path:
    candidates = [
        Path("/home/kimjisu/download/mitmdump"),
        Path(shutil.which("mitmdump") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find mitmdump. Expected /home/kimjisu/download/mitmdump.")


def relay_tty(
    master_fd: int,
    child: subprocess.Popen[bytes],
    *,
    dataset_session: DatasetSessionPaths | None = None,
) -> int:
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    old_tty = termios.tcgetattr(stdin_fd) if os.isatty(stdin_fd) else None
    if old_tty is not None:
        tty.setraw(stdin_fd)
    # Ensure TUI apps see a valid initial window size (gVisor can return 0x0
    # otherwise, leading to a blank screen).
    sync_pty_winsize(master_fd)
    old_sigwinch = None
    try:
        old_sigwinch = signal.getsignal(signal.SIGWINCH)
    except Exception:
        old_sigwinch = None

    def _on_winch(_signum: int, _frame: object | None = None) -> None:  # pragma: no cover
        sync_pty_winsize(master_fd)

    with suppress(Exception):
        signal.signal(signal.SIGWINCH, _on_winch)
    try:
        while True:
            readable, _, _ = select.select([stdin_fd, master_fd], [], [], 0.1)
            if master_fd in readable:
                try:
                    data = os.read(master_fd, 65536)
                except OSError:
                    break
                if not data:
                    break
                if dataset_session is not None:
                    with suppress(Exception):
                        record_terminal_chunk(dataset_session, stream="stdout", data=data)
                os.write(stdout_fd, data)
            if stdin_fd in readable:
                data = os.read(stdin_fd, 65536)
                if not data:
                    break
                if dataset_session is not None:
                    with suppress(Exception):
                        record_terminal_chunk(dataset_session, stream="stdin", data=data)
                os.write(master_fd, data)
            if child.poll() is not None and not readable:
                break
    finally:
        with suppress(Exception):
            if old_sigwinch is not None:
                signal.signal(signal.SIGWINCH, old_sigwinch)
        if old_tty is not None:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_tty)
        with suppress(OSError):
            os.close(master_fd)
    return child.wait()


def wait_for_http_ready(port: int, timeout: float) -> None:
    import urllib.request

    deadline = time.time() + timeout
    url = f"http://127.0.0.1:{port}/api/health"
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as response:
                payload = json.loads(response.read().decode())
                if payload.get("ok"):
                    return
        except Exception:
            time.sleep(0.2)
    raise RuntimeError(f"broker did not become ready on port {port}")


def wait_for_tcp_ready(host: str, port: int, timeout: float) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(1)
            sock.connect((host, port))
            return
        except OSError:
            time.sleep(0.2)
        finally:
            sock.close()
    raise RuntimeError(f"service did not become ready on {host}:{port}")


def discover_host_ip() -> str:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    finally:
        sock.close()


def reserve_tcp_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])
    finally:
        sock.close()


def spawn_broker(
    socket_path: Path,
    web_port: int,
    decision_timeout: float,
    bind_host: str,
    http_socket_path: Path,
    tcp_port: int,
    log_path: Path,
    event_log_path: Path | None,
    decision_dir: Path | None,
    llm_log_path: Path | None,
    llm_proxy_url: str | None,
) -> subprocess.Popen[bytes]:
    command = [
        sys.executable,
        "-m",
        "gvisor_hook",
        "serve",
        "--socket-path",
        str(socket_path),
        "--web-port",
        str(web_port),
        "--decision-timeout",
        str(decision_timeout),
        "--bind-host",
        bind_host,
        "--http-socket-path",
        str(http_socket_path),
        "--tcp-host",
        "127.0.0.1",
        "--tcp-port",
        str(tcp_port),
    ]
    if event_log_path is not None and decision_dir is not None:
        command.extend(
            [
                "--event-log-path",
                str(event_log_path),
                "--decision-dir",
                str(decision_dir),
            ]
        )
    if llm_log_path is not None:
        command.extend(["--llm-log-path", str(llm_log_path)])
    if llm_proxy_url is not None:
        command.extend(["--llm-proxy-url", llm_proxy_url])
    log_path.parent.mkdir(parents=True, exist_ok=True)
    broker_log = log_path.open("a", encoding="utf-8")
    return subprocess.Popen(
        command,
        cwd=str(Path(__file__).resolve().parent.parent),
        stdin=subprocess.DEVNULL,
        stdout=broker_log,
        stderr=subprocess.STDOUT,
    )


def spawn_mitmdump(
    mitmdump_bin: Path,
    listen_port: int,
    log_path: Path,
    llm_log_path: Path,
    dataset_session: DatasetSessionPaths,
) -> subprocess.Popen[bytes]:
    addon_path = Path(__file__).resolve().parent / "mitm_addon.py"
    repo_root = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    env["GVISOR_HOOK_LLM_LOG_PATH"] = str(llm_log_path)
    env["GVISOR_HOOK_DATASET_SESSION_DIR"] = str(dataset_session.session_root)
    env["GVISOR_HOOK_DATASET_ROOT"] = str(dataset_session.dataset_root)
    env["GVISOR_HOOK_SESSION_ID"] = dataset_session.session_id
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = (
        f"{repo_root}:{existing_pythonpath}" if existing_pythonpath else str(repo_root)
    )
    mitm_log = log_path.open("a", encoding="utf-8")
    return subprocess.Popen(
        [
            str(mitmdump_bin),
            "--listen-host",
            "127.0.0.1",
            "--listen-port",
            str(listen_port),
            "--set",
            "block_global=false",
            "--set",
            "termlog_verbosity=warn",
            "-s",
            str(addon_path),
        ],
        cwd=str(Path(__file__).resolve().parent.parent),
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=mitm_log,
        stderr=subprocess.STDOUT,
    )


def make_runtime_dir(workdir: Path) -> Path:
    base = workdir / ".gvisor-hook"
    base.mkdir(parents=True, exist_ok=True)
    runtime_dir = Path(tempfile.mkdtemp(prefix="run-", dir=base))
    runtime_dir.chmod(0o755)
    return runtime_dir


def write_runtime_network_files(runtime_dir: Path) -> tuple[Path, Path, Path]:
    network_dir = runtime_dir / "network"
    network_dir.mkdir(parents=True, exist_ok=True)

    resolv_path = network_dir / "resolv.conf"
    host_resolv = Path("/etc/resolv.conf")
    try:
        host_resolv_contents = host_resolv.read_text(encoding="utf-8")
    except Exception:
        host_resolv_contents = ""
    if "nameserver" not in host_resolv_contents:
        host_resolv_contents = ""

    public_fallback = [
        "nameserver 1.1.1.1",
        "nameserver 8.8.8.8",
        "options timeout:2 attempts:2",
    ]
    filtered_lines: list[str] = []
    for line in host_resolv_contents.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("nameserver "):
            _, _, addr = stripped.partition(" ")
            try:
                ip = ipaddress.ip_address(addr.strip())
            except ValueError:
                continue
            # WSL often injects a synthetic resolver (for example 10.255.255.254)
            # that is not reachable from inside gVisor's rootless sandbox.
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                continue
        filtered_lines.append(stripped)
    resolv_lines = filtered_lines + [line for line in public_fallback if line not in filtered_lines]
    resolv_path.write_text("\n".join(resolv_lines) + "\n", encoding="utf-8")

    hosts_path = network_dir / "hosts"
    hosts_src = Path("/etc/hosts")
    hosts_path.write_text(hosts_src.read_text(encoding="utf-8"), encoding="utf-8")

    nsswitch_path = network_dir / "nsswitch.conf"
    nsswitch_src = Path("/etc/nsswitch.conf")
    nsswitch_path.write_text(nsswitch_src.read_text(encoding="utf-8"), encoding="utf-8")
    return resolv_path, hosts_path, nsswitch_path


def write_bootstrap_files(runtime_dir: Path) -> Path:
    bootstrap_dir = runtime_dir / "bootstrap"
    bootstrap_dir.mkdir(parents=True, exist_ok=True)
    sitecustomize_path = bootstrap_dir / "sitecustomize.py"
    sitecustomize_path.write_text(
        """from __future__ import annotations

import os
import socket
from pathlib import Path

TARGET = Path("/tmp/host-run/proxy-http.sock")
OPENAI_PROXY_HOST = "127.0.0.1"
OPENAI_PROXY_PORT = 18080


def log(message: str) -> None:
    try:
        with open("/tmp/host-run/python-proxy.log", "a", encoding="utf-8") as fh:
            fh.write(message + "\\n")
    except OSError:
        pass


def install_unix_socket_proxy() -> None:
    original_create_connection = socket.create_connection

    def create_connection(address, timeout=None, source_address=None):
        try:
            host, port = address
        except Exception:
            return original_create_connection(address, timeout, source_address)
        if host == OPENAI_PROXY_HOST and int(port) == OPENAI_PROXY_PORT:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(str(TARGET))
            return sock
        return original_create_connection(address, timeout, source_address)

    socket.create_connection = create_connection

    try:
        from httpcore._backends.sync import SyncBackend, SyncStream
    except Exception as exc:  # pragma: no cover
        log(f"httpcore import failed, stdlib socket patch still active: {exc!r}")
        return

    original_connect_tcp = SyncBackend.connect_tcp

    def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        if host == OPENAI_PROXY_HOST and int(port) == OPENAI_PROXY_PORT:
            sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect(str(TARGET))
            return SyncStream(sock)
        return original_connect_tcp(
            self,
            host,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    SyncBackend.connect_tcp = connect_tcp
    log(f"installed unix socket proxy for {OPENAI_PROXY_HOST}:{OPENAI_PROXY_PORT} -> {TARGET}")


if TARGET.exists():
    install_unix_socket_proxy()
else:
    log(f"unix socket target missing: {TARGET}")
""",
        encoding="utf-8",
    )
    diagnostics_path = bootstrap_dir / "README.txt"
    diagnostics_path.write_text(
        "Bootstrap files mounted into the sandbox. sitecustomize.py installs a Unix socket transport for OpenAI proxy calls.\\n",
        encoding="utf-8",
    )
    return bootstrap_dir


def resolve_dataset_root(dataset_root: str | None) -> Path:
    if dataset_root:
        return Path(dataset_root).expanduser().resolve()
    return default_dataset_root()


def launch(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    if not workdir.is_dir():
        raise FileNotFoundError(f"workdir does not exist: {workdir}")

    agent_argv: list[str] | None = None
    raw_agent_cmd = getattr(args, "agent_cmd", None)
    if raw_agent_cmd:
        agent_argv = shlex.split(raw_agent_cmd)
        if agent_argv and agent_argv[0] in {"codex", "/usr/local/bin/codex"}:
            agent_argv = [
                "/usr/bin/node",
                "/usr/local/lib/node_modules/@openai/codex/bin/codex.js",
                *agent_argv[1:],
            ]
    else:
        prompt = getattr(args, "prompt", None)
        if not prompt:
            raise ValueError('Provide --agent-cmd or --prompt (for default "codex exec" mode).')
        agent_argv = [
            "/usr/bin/node",
            "/usr/local/lib/node_modules/@openai/codex/bin/codex.js",
            "exec",
            "--skip-git-repo-check",
            "-C",
            "/tmp/workspace",
        ]
        codex_model = getattr(args, "codex_model", None)
        if codex_model:
            agent_argv.extend(["--model", codex_model])
        if not getattr(args, "codex_no_json", False):
            agent_argv.append("--json")
        agent_argv.append(prompt)

    runtime_dir = make_runtime_dir(workdir)
    approval_ipc_dir = Path("/tmp") / f"gvisor-hook-{runtime_dir.name}"
    approval_ipc_dir.mkdir(parents=True, exist_ok=True)
    approval_ipc_dir.chmod(0o777)
    bundle_dir = runtime_dir / "bundle"
    broker_socket_path = approval_ipc_dir / "broker.sock"
    proxy_http_socket_path = runtime_dir / "proxy-http.sock"
    console_socket_path = runtime_dir / "console.sock"
    runsc_root = runtime_dir / "runsc-root"
    runsc_root.mkdir(parents=True, exist_ok=True)

    container_id = f"open-interpreter-{int(time.time())}"
    dataset_root = resolve_dataset_root(getattr(args, "dataset_root", None))
    plan_mode_enabled = not getattr(args, "no_plan_mode", False)
    custom_instructions = DATASET_PLAN_INSTRUCTIONS if plan_mode_enabled else None
    dataset_session = create_dataset_session(
        dataset_root,
        make_session_id(container_id),
        {
            "workdir": str(workdir),
            "runtime_dir": str(runtime_dir),
            "container_id": container_id,
            "web_port": args.web_port,
            "decision_timeout": args.decision_timeout,
            "profile": "default.yaml",
            "plan_mode_enabled": plan_mode_enabled,
            "custom_instructions": custom_instructions,
        },
    )
    runsc_logs_dir = dataset_session.session_root / "runsc-logs"
    runsc_logs_dir.mkdir(parents=True, exist_ok=True)
    with suppress(Exception):
        manifest = json.loads(dataset_session.manifest_path.read_text(encoding="utf-8"))
        manifest.setdefault("logs", {}).update(
            {
                "runsc_logs_dir": str(runsc_logs_dir),
                "runsc_debug_log_path": str(runsc_logs_dir / "debug"),
                "runsc_user_log_path": str(runsc_logs_dir / "user.log"),
            }
        )
        dataset_session.manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        append_ndjson(
            dataset_session.session_index_path,
            {
                "type": "runsc-logs-configured",
                "payload": {
                    "configured_at": utc_now(),
                    "runsc_logs_dir": str(runsc_logs_dir),
                },
            },
        )
    broker_log_path = dataset_session.broker_log_path
    llm_log_path = dataset_session.llm_ui_log_path
    mitm_log_path = dataset_session.mitm_log_path
    host_ip = discover_host_ip()
    broker_tcp_port = reserve_tcp_port()
    mitm_tcp_port = reserve_tcp_port()
    runsc_bin = Path(args.runsc_bin).resolve() if args.runsc_bin else find_runsc_binary()
    mitmdump_bin = find_mitmdump_binary()
    broker_proc = None
    mitm_proc = None
    runsc_proc = None
    console_server = None
    try:
        mitm_proc = spawn_mitmdump(
            mitmdump_bin,
            mitm_tcp_port,
            mitm_log_path,
            llm_log_path,
            dataset_session,
        )
        wait_for_tcp_ready("127.0.0.1", mitm_tcp_port, timeout=10)
        broker_proc = spawn_broker(
            broker_socket_path,
            args.web_port,
            args.decision_timeout,
            host_ip,
            proxy_http_socket_path,
            broker_tcp_port,
            broker_log_path,
            None,
            None,
            llm_log_path,
            f"http://127.0.0.1:{mitm_tcp_port}",
        )
        wait_for_http_ready(args.web_port, timeout=10)
        resolv_path, hosts_path, nsswitch_path = write_runtime_network_files(runtime_dir)
        bootstrap_dir = write_bootstrap_files(runtime_dir)
        # The sandbox uses host networking (via runsc `--network=host` plus an OCI spec
        # without a network namespace), so loopback reaches the host-side broker.
        proxy_base_url = f"http://127.0.0.1:{args.web_port}/openai/v1"
        upstream_proxy_url = f"http://127.0.0.1:{mitm_tcp_port}"

        # Codex CLI defaults to api.openai.com and may use websockets for the responses API.
        # To guarantee broker/mitm capture (and avoid sandbox DNS issues), force:
        # - base URL to the local broker reverse proxy
        # - websockets off (use HTTP/SSE instead)
        if agent_argv and len(agent_argv) >= 2 and agent_argv[1].endswith("/codex.js"):
            # Codex's built-in `openai` provider currently prefers WebSocket transport,
            # and `supports_websockets=false` may not disable it for that provider.
            # To guarantee HTTP/SSE (so the mitmproxy addon can log full bodies),
            # force a custom provider with websockets disabled.
            #
            # See: https://github.com/openai/codex/issues/13103
            has_model_provider = any(token.startswith("model_provider=") for token in agent_argv)
            has_custom_provider_base = any(
                token.startswith("model_providers.openai_custom.base_url=")
                or token.startswith('model_providers.openai_custom.base_url="')
                for token in agent_argv
            )
            has_custom_provider_ws = any(
                token.startswith("model_providers.openai_custom.supports_websockets=") for token in agent_argv
            )
            inject: list[str] = []
            if not has_model_provider:
                inject.extend(["-c", 'model_provider="openai_custom"'])
            if not has_custom_provider_base:
                inject.extend(["-c", f'model_providers.openai_custom.base_url="{proxy_base_url}"'])
                inject.extend(["-c", 'model_providers.openai_custom.env_key="OPENAI_API_KEY"'])
                inject.extend(["-c", 'model_providers.openai_custom.name="OpenAI (broker)"'])
                inject.extend(["-c", "model_providers.openai_custom.requires_openai_auth=true"])
            if not has_custom_provider_ws:
                inject.extend(["-c", "model_providers.openai_custom.supports_websockets=false"])
            if inject:
                agent_argv = [agent_argv[0], agent_argv[1], *inject, *agent_argv[2:]]
        write_bundle_config(
            bundle_dir,
            workdir=workdir,
            runtime_home_dir="/home",
            container_id=container_id,
            resolv_conf_path=str(resolv_path),
            hosts_path=str(hosts_path),
            nsswitch_conf_path=str(nsswitch_path),
            proxy_base_url=proxy_base_url,
            upstream_proxy_url=None,
            agent_argv=agent_argv,
            hook_timeout_ms=int(args.decision_timeout * 1000),
            hook_warmup_ms=20000,
            hook_container_id=container_id,
            profile="default.yaml",
            custom_instructions=custom_instructions,
        )
        config_path = bundle_dir / "config.json"
        config = json.loads(config_path.read_text(encoding="utf-8"))
        config["process"]["env"] = [
            entry
            for entry in config["process"]["env"]
            if not entry.startswith("GVISOR_HOOK_ADDR=")
            and not entry.startswith("GVISOR_HOOK_SOCKET=")
            and not entry.startswith("GVISOR_HOOK_EVENT_LOG=")
            and not entry.startswith("GVISOR_HOOK_DECISION_DIR=")
        ]
        config["mounts"].append(
            {
                "destination": "/tmp/bootstrap",
                "type": "bind",
                "source": str(bootstrap_dir),
                "options": ["rbind", "ro"],
            }
        )
        config["mounts"].append(
            {
                "destination": "/tmp/host-run",
                "type": "bind",
                "source": str(runtime_dir),
                "options": ["rbind", "rw"],
            }
        )
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        console_server = ConsoleSocketServer(console_socket_path)

        env = os.environ.copy()
        env.update(
            {
                "GVISOR_HOOK_ADDR": f"127.0.0.1:{broker_tcp_port}",
                "GVISOR_HOOK_TIMEOUT_MS": str(int(args.decision_timeout * 1000)),
                "GVISOR_HOOK_WARMUP_MS": "20000",
                "GVISOR_HOOK_CONTAINER_ID": container_id,
            }
        )

        print(f"Approval UI: http://127.0.0.1:{args.web_port}", file=sys.stderr)
        print(f"OpenAI base (broker): {proxy_base_url}", file=sys.stderr)
        print(f"HTTP(S) proxy (mitm): {upstream_proxy_url}", file=sys.stderr)
        print(f"Dataset session: {dataset_session.session_root}", file=sys.stderr)
        print(f"runsc logs: {runsc_logs_dir}", file=sys.stderr)
        runsc_cmd: list[str] = [
            str(runsc_bin),
            "--ignore-cgroups",
            "--rootless",
            "--network=host",
            "--host-uds=all",
            "--debug-log",
            str(runsc_logs_dir / "debug"),
        ]
        if getattr(args, "runsc_strace", False):
            runsc_cmd.append("--strace")
            syscalls = (getattr(args, "runsc_strace_syscalls", "") or "").strip()
            if syscalls:
                runsc_cmd.extend(["--strace-syscalls", syscalls])
        runsc_cmd.extend(
            [
                "--root",
                str(runsc_root),
                "run",
                "--bundle",
                str(bundle_dir),
                "--console-socket",
                str(console_socket_path),
                "--user-log",
                str(runsc_logs_dir / "user.log"),
                container_id,
            ]
        )
        runsc_proc = subprocess.Popen(runsc_cmd, env=env)
        master_fd = console_server.accept_master_fd_until_process_exit(
            timeout=15, child=runsc_proc
        )
        return relay_tty(master_fd, runsc_proc, dataset_session=dataset_session)
    finally:
        if console_server is not None:
            console_server.close()
        if runsc_proc is not None and runsc_proc.poll() is None:
            with suppress(Exception):
                runsc_proc.send_signal(signal.SIGTERM)
                runsc_proc.wait(timeout=5)
        if broker_proc is not None and broker_proc.poll() is None:
            with suppress(Exception):
                broker_proc.send_signal(signal.SIGTERM)
                broker_proc.wait(timeout=5)
        if mitm_proc is not None and mitm_proc.poll() is None:
            with suppress(Exception):
                mitm_proc.send_signal(signal.SIGTERM)
                mitm_proc.wait(timeout=5)
        with suppress(Exception):
            append_ndjson(
                dataset_session.session_index_path,
                {
                    "type": "session-ended",
                    "payload": {
                        "ended_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                        "runsc_returncode": None if runsc_proc is None else runsc_proc.poll(),
                        "broker_returncode": None if broker_proc is None else broker_proc.poll(),
                        "mitm_returncode": None if mitm_proc is None else mitm_proc.poll(),
                    },
                },
            )
