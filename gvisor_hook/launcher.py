from __future__ import annotations

import argparse
import ipaddress
import json
import os
import select
import shlex
import shutil
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import termios
import time
import tty
from dataclasses import dataclass
from contextlib import suppress
from pathlib import Path

from .bundle import write_bundle_config


@dataclass(frozen=True)
class MountSpec:
    source: Path
    destination: str
    recursive: bool = True
    writable: bool = False

    def to_oci_mount(self) -> dict[str, object]:
        mode = "rw" if self.writable else "ro"
        bind_mode = "rbind" if self.recursive else "bind"
        return {
            "destination": self.destination,
            "type": "bind",
            "source": str(self.source),
            "options": [bind_mode, mode],
        }


@dataclass(frozen=True)
class ResolvedAgent:
    name: str
    host_command: Path
    container_command: str
    process_args: list[str]
    mount_specs: list[MountSpec]
    python_path_entries: list[str]


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
    project_root = Path(__file__).resolve().parent.parent
    candidates = [
        project_root / "third_party/gvisor/bin/runsc-hook",
        project_root / "third_party/gvisor/bazel-bin/runsc/runsc_/runsc",
        Path(shutil.which("runsc") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find a custom runsc binary. Build it first with scripts/build_runsc.sh.")


def find_mitmdump_binary() -> Path:
    candidates = [
        Path.home() / "download/mitmdump",
        Path(shutil.which("mitmdump") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find mitmdump. Install it or add it to PATH.")


def sanitize_name(value: str) -> str:
    sanitized = "".join(char if char.isalnum() else "-" for char in value.lower()).strip("-")
    return sanitized or "agent"


def iter_config_dir_candidates(agent_name: str, home_dir: Path) -> list[Path]:
    return [
        home_dir / f".{agent_name}",
        home_dir / agent_name,
        home_dir / ".config" / agent_name,
    ]


def prompt_for_config_mount(agent_name: str) -> Path | None:
    if not sys.stdin.isatty():
        return None
    response = input(
        f"Config directory for '{agent_name}' was not found automatically. "
        "Enter a directory path to mount, or press Enter to continue without one: "
    ).strip()
    if not response:
        return None
    candidate = Path(response).expanduser().resolve()
    if not candidate.is_dir():
        raise FileNotFoundError(f"Config directory does not exist: {candidate}")
    return candidate


def resolve_config_mount(agent_name: str, override: str | None, runtime_home_dir: str) -> MountSpec | None:
    home_dir = Path.home()
    candidates: list[Path]
    if override:
        candidates = [Path(override).expanduser().resolve()]
    else:
        candidates = iter_config_dir_candidates(agent_name, home_dir)
    for candidate in candidates:
        if candidate.is_dir():
            try:
                relative = candidate.relative_to(home_dir)
            except ValueError:
                relative = Path(".config") / agent_name
            return MountSpec(
                source=candidate,
                destination=f"{runtime_home_dir}/{relative.as_posix()}",
                recursive=True,
                writable=True,
            )
    prompted = prompt_for_config_mount(agent_name)
    if prompted is None:
        return None
    try:
        relative = prompted.relative_to(home_dir)
    except ValueError:
        relative = Path(".config") / agent_name
    return MountSpec(
        source=prompted,
        destination=f"{runtime_home_dir}/{relative.as_posix()}",
        recursive=True,
        writable=True,
    )


def parse_shebang_command(command_path: Path) -> list[str]:
    try:
        with command_path.open("r", encoding="utf-8") as fh:
            first_line = fh.readline().strip()
    except UnicodeDecodeError:
        return []
    if not first_line.startswith("#!"):
        return []
    return shlex.split(first_line[2:].strip())


def resolve_python_from_shebang(command_path: Path) -> Path | None:
    parts = parse_shebang_command(command_path)
    if not parts:
        return None
    interpreter = parts[0]
    if Path(interpreter).name == "env":
        for token in parts[1:]:
            if token.startswith("-") or "=" in token:
                continue
            interpreter = token
            break
    if "python" not in Path(interpreter).name.lower():
        return None
    interpreter_path = Path(interpreter)
    if interpreter_path.is_absolute() and interpreter_path.exists():
        return interpreter_path
    resolved = shutil.which(interpreter)
    return Path(resolved).resolve() if resolved else None


def discover_python_site_packages(python_bin: Path) -> list[Path]:
    probe = (
        "import json, site; "
        "paths = []; "
        "getsitepackages = getattr(site, 'getsitepackages', lambda: []); "
        "paths.extend(getsitepackages()); "
        "usersite = getattr(site, 'getusersitepackages', lambda: None)(); "
        "paths.extend(usersite if isinstance(usersite, list) else [usersite] if usersite else []); "
        "print(json.dumps(paths))"
    )
    result = subprocess.run(
        [str(python_bin), "-c", probe],
        check=True,
        capture_output=True,
        text=True,
    )
    paths = json.loads(result.stdout)
    unique_paths: list[Path] = []
    seen: set[str] = set()
    for raw_path in paths:
        if not raw_path:
            continue
        candidate = Path(raw_path).expanduser().resolve()
        key = str(candidate)
        if key in seen or not candidate.is_dir():
            continue
        seen.add(key)
        unique_paths.append(candidate)
    return unique_paths


def build_process_args(agent_name: str, container_command: str, proxy_base_url: str) -> list[str]:
    args = [container_command]
    if agent_name == "interpreter":
        args.extend(["--api_base", proxy_base_url])
    return args


def resolve_agent(args: argparse.Namespace, runtime_home_dir: str) -> ResolvedAgent:
    resolved_command = shutil.which(args.agent_cmd)
    if not resolved_command:
        raise FileNotFoundError(f"Could not find agent command '{args.agent_cmd}' in PATH.")

    host_command = Path(resolved_command).resolve()
    agent_name = sanitize_name(host_command.name)
    container_bin_dir = "/tmp/agent/bin"
    container_command = f"{container_bin_dir}/{host_command.name}"
    mount_specs = [
        MountSpec(
            source=host_command,
            destination=container_command,
            recursive=False,
            writable=False,
        ),
    ]
    config_mount = resolve_config_mount(agent_name, args.config_mount, runtime_home_dir)
    if config_mount is not None:
        mount_specs.append(config_mount)

    python_path_entries: list[str] = []
    python_site_packages = (
        [Path(args.python_site_packages).expanduser().resolve()]
        if args.python_site_packages
        else []
    )
    if not python_site_packages:
        python_bin = resolve_python_from_shebang(host_command)
        if python_bin is not None:
            python_site_packages = discover_python_site_packages(python_bin)
    for index, site_packages_dir in enumerate(python_site_packages):
        destination = f"/tmp/python/site-packages/{index}"
        mount_specs.append(
            MountSpec(
                source=site_packages_dir,
                destination=destination,
                recursive=True,
                writable=False,
            )
        )
        python_path_entries.append(destination)

    return ResolvedAgent(
        name=agent_name,
        host_command=host_command,
        container_command=container_command,
        process_args=build_process_args(agent_name, container_command, "http://127.0.0.1:18080/openai/v1"),
        mount_specs=mount_specs,
        python_path_entries=python_path_entries,
    )


def relay_tty(master_fd: int, child: subprocess.Popen[bytes]) -> int:
    stdin_fd = sys.stdin.fileno()
    stdout_fd = sys.stdout.fileno()
    old_tty = termios.tcgetattr(stdin_fd) if os.isatty(stdin_fd) else None
    if old_tty is not None:
        tty.setraw(stdin_fd)
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
                os.write(stdout_fd, data)
            if stdin_fd in readable:
                data = os.read(stdin_fd, 65536)
                if not data:
                    break
                os.write(master_fd, data)
            if child.poll() is not None and not readable:
                break
    finally:
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
) -> subprocess.Popen[bytes]:
    addon_path = Path(__file__).resolve().parent / "mitm_addon.py"
    env = os.environ.copy()
    env["GVISOR_HOOK_LLM_LOG_PATH"] = str(llm_log_path)
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


def launch(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    if not workdir.is_dir():
        raise FileNotFoundError(f"workdir does not exist: {workdir}")

    runtime_dir = make_runtime_dir(workdir)
    approval_ipc_dir = Path("/tmp") / f"gvisor-hook-{runtime_dir.name}"
    approval_ipc_dir.mkdir(parents=True, exist_ok=True)
    approval_ipc_dir.chmod(0o777)
    bundle_dir = runtime_dir / "bundle"
    broker_socket_path = approval_ipc_dir / "broker.sock"
    proxy_http_socket_path = runtime_dir / "proxy-http.sock"
    broker_log_path = runtime_dir / "broker.log"
    llm_log_path = runtime_dir / "llm.ndjson"
    mitm_log_path = runtime_dir / "mitmproxy.log"
    console_socket_path = runtime_dir / "console.sock"
    runsc_root = runtime_dir / "runsc-root"
    debug_log_dir = runtime_dir / "runsc-logs"
    runsc_root.mkdir(parents=True, exist_ok=True)
    debug_log_dir.mkdir(parents=True, exist_ok=True)

    runtime_home_dir = "/tmp/agent-home"
    resolved_agent = resolve_agent(args, runtime_home_dir)
    container_id = f"{resolved_agent.name}-{int(time.time())}"
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
        write_bundle_config(
            bundle_dir,
            workdir=workdir,
            runtime_home_dir=runtime_home_dir,
            container_id=container_id,
            process_args=resolved_agent.process_args,
            agent_bin_dir="/tmp/agent/bin",
            extra_mounts=[mount_spec.to_oci_mount() for mount_spec in resolved_agent.mount_specs],
            python_path_entries=resolved_agent.python_path_entries,
            resolv_conf_path=str(resolv_path),
            hosts_path=str(hosts_path),
            nsswitch_conf_path=str(nsswitch_path),
            proxy_base_url="http://127.0.0.1:18080/openai/v1",
            hook_timeout_ms=int(args.decision_timeout * 1000),
            hook_warmup_ms=5000,
            hook_container_id=container_id,
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
                "GVISOR_HOOK_WARMUP_MS": "5000",
                "GVISOR_HOOK_CONTAINER_ID": container_id,
            }
        )

        print(f"Agent command: {resolved_agent.host_command}", file=sys.stderr)
        print(f"Approval UI: http://127.0.0.1:{args.web_port}", file=sys.stderr)
        print("Sandbox proxy base: http://127.0.0.1:18080/openai/v1 (intercepted to Unix socket)", file=sys.stderr)
        print(f"LLM MITM: http://127.0.0.1:{mitm_tcp_port}", file=sys.stderr)
        print(f"runsc logs: {debug_log_dir}", file=sys.stderr)
        runsc_proc = subprocess.Popen(
            [
                str(runsc_bin),
                "--ignore-cgroups",
                "--rootless",
                "--network=host",
                "--host-uds=all",
                "--debug-log",
                str(debug_log_dir / "debug"),
                "--root",
                str(runsc_root),
                "run",
                "--bundle",
                str(bundle_dir),
                "--console-socket",
                str(console_socket_path),
                "--user-log",
                str(debug_log_dir / "user.log"),
                container_id,
            ],
            env=env,
        )
        master_fd = console_server.accept_master_fd_until_process_exit(
            timeout=15, child=runsc_proc
        )
        return relay_tty(master_fd, runsc_proc)
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
