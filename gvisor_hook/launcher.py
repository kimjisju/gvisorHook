from __future__ import annotations

import argparse
import ipaddress
import json
import fcntl
import os
import re
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
from .reason_pipeline import default_reason_pipeline_dir, model_learning_cap_reason_results_dir

HOOK_WARMUP_MS = int(os.environ.get("GVISOR_HOOK_WARMUP_MS_DEFAULT", "3000"))
MIN_HOOK_TIMEOUT_MS = 360000

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
        Path(shutil.which("runsc") or ""),
    ]
    for candidate in candidates:
        if candidate and candidate.exists():
            return candidate
    raise FileNotFoundError("Could not find a custom runsc binary. Build it first with scripts/build_runsc.sh.")


def find_mitmdump_binary() -> Path:
    candidates = [
        Path.home() / "download" / "mitmdump",
    ]
    resolved = shutil.which("mitmdump")
    if resolved:
        candidates.append(Path(resolved))
    for candidate in candidates:
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError("Could not find mitmdump. Install it or add it to PATH.")


def check_mitmdump_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [*command, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
    )


def iter_mitmdump_python_fallbacks(mitmdump_bin: Path) -> list[Path]:
    try:
        with mitmdump_bin.open("r", encoding="utf-8") as fh:
            first_line = fh.readline().strip()
    except (OSError, UnicodeDecodeError):
        return []
    if not first_line.startswith("#!"):
        return []
    parts = shlex.split(first_line[2:].strip())
    if not parts:
        return []
    interpreter = Path(parts[0]).name
    if interpreter == "env" and len(parts) > 1:
        interpreter = parts[1]
    if Path(interpreter).name != "python3":
        return []

    fallbacks: list[Path] = []
    for name in ("python3.10", "python3.11"):
        resolved = shutil.which(name)
        if resolved:
            fallbacks.append(Path(resolved).resolve())
    return fallbacks


def find_mitmdump_command() -> list[str]:
    mitmdump_bin = find_mitmdump_binary()
    direct_command = [str(mitmdump_bin)]
    direct_result = check_mitmdump_command(direct_command)
    if direct_result.returncode == 0:
        return direct_command

    for python_bin in iter_mitmdump_python_fallbacks(mitmdump_bin):
        fallback_command = [str(python_bin), str(mitmdump_bin)]
        fallback_result = check_mitmdump_command(fallback_command)
        if fallback_result.returncode == 0:
            return fallback_command

    output = (direct_result.stdout + direct_result.stderr).strip()
    raise RuntimeError(f"mitmdump is installed but failed to start:\n{output}")


def find_mitmproxy_ca_cert() -> Path:
    cert_path = Path.home() / ".mitmproxy" / "mitmproxy-ca-cert.pem"
    if cert_path.is_file():
        return cert_path.resolve()
    raise FileNotFoundError(
        f"Could not find mitmproxy CA certificate at {cert_path}. "
        "Start mitmdump once so it can generate its CA files, then retry."
    )


def parse_shebang_command(command_path: Path) -> list[str]:
    try:
        with command_path.open("r", encoding="utf-8") as fh:
            first_line = fh.readline().strip()
    except (OSError, UnicodeDecodeError):
        return []
    if not first_line.startswith("#!"):
        return []
    return shlex.split(first_line[2:].strip())


def resolve_path_executable(name: str, *, preferred_dirs: list[Path] | None = None) -> Path | None:
    for directory in preferred_dirs or []:
        candidate = (directory / name).resolve()
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    resolved = shutil.which(name)
    if not resolved:
        return None
    path = Path(resolved).resolve()
    if path.is_file() and os.access(path, os.X_OK):
        return path
    return None


def resolve_env_interpreter_from_shebang(
    command_path: Path,
    *,
    preferred_dirs: list[Path] | None = None,
) -> Path | None:
    parts = parse_shebang_command(command_path)
    if not parts or Path(parts[0]).name != "env":
        return None
    for token in parts[1:]:
        if token.startswith("-") or "=" in token:
            continue
        resolved = resolve_path_executable(token, preferred_dirs=preferred_dirs)
        if not resolved:
            raise FileNotFoundError(
                f"Could not find shebang interpreter '{token}' required by {command_path} in PATH."
            )
        return resolved
    return None


def shell_wrapper_uses_node(command_path: Path) -> bool:
    parts = parse_shebang_command(command_path)
    if not parts or Path(parts[0]).name not in {"sh", "bash", "dash"}:
        return False
    try:
        content = command_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return bool(re.search(r"(?m)^\s*(?:exec\s+)?node(?:\s|$)", content))


def resolve_node_for_shell_wrapper(
    command_path: Path,
    *,
    preferred_dirs: list[Path] | None = None,
) -> Path | None:
    if not shell_wrapper_uses_node(command_path):
        return None
    for name in ("node", "nodejs"):
        resolved = resolve_path_executable(name, preferred_dirs=preferred_dirs)
        if resolved is not None:
            return resolved
    raise FileNotFoundError(
        f"{command_path} is a shell wrapper that runs 'node', but no executable node was found in PATH."
    )


def iter_config_dir_candidates(agent_name: str, home_dir: Path) -> list[Path]:
    return [
        home_dir / f".{agent_name}",
        home_dir / agent_name,
        home_dir / ".config" / agent_name,
    ]


def resolve_config_mount(agent_name: str, runtime_home_dir: str) -> dict[str, object] | None:
    home_dir = Path.home()
    for candidate in iter_config_dir_candidates(agent_name, home_dir):
        if candidate.is_dir():
            try:
                relative = candidate.relative_to(home_dir)
            except ValueError:
                relative = Path(".config") / agent_name
            return {
                "destination": f"{runtime_home_dir}/{relative.as_posix()}",
                "type": "bind",
                "source": str(candidate),
                "options": ["rbind", "rw"],
            }
    return None


def find_node_modules_root(path: Path) -> Path | None:
    for parent in [path.parent, *path.parents]:
        if parent.name == "node_modules":
            return parent
    return None


def resolve_agent_argv_and_mounts(
    agent_argv: list[str] | None,
    runtime_home_dir: str,
) -> tuple[list[str] | None, list[dict[str, object]]]:
    if not agent_argv:
        return agent_argv, []

    command = agent_argv[0]
    resolved = command if Path(command).is_absolute() else shutil.which(command)
    if not resolved:
        return agent_argv, []

    resolved_command = Path(resolved)
    host_command = resolved_command.resolve()
    preferred_interpreter_dirs = [resolved_command.parent.resolve()]
    node_modules_root = find_node_modules_root(host_command)
    container_bin_dir = "/tmp/agent/bin"
    if node_modules_root is not None:
        container_command = f"/tmp/agent/node_modules/{host_command.relative_to(node_modules_root).as_posix()}"
    else:
        container_command = f"{container_bin_dir}/{host_command.name}"
    mounts: list[dict[str, object]] = []

    if parse_shebang_command(host_command):
        mounts.append(
            {
                "destination": container_bin_dir,
                "type": "bind",
                "source": str(host_command.parent),
                "options": ["rbind", "ro"],
            }
        )
        if node_modules_root is not None:
            mounts.append(
                {
                    "destination": "/tmp/agent/node_modules",
                    "type": "bind",
                    "source": str(node_modules_root),
                    "options": ["rbind", "ro"],
                }
            )
    else:
        mounts.append(
            {
                "destination": container_command,
                "type": "bind",
                "source": str(host_command),
                "options": ["bind", "ro"],
            }
        )

    env_interpreter = resolve_env_interpreter_from_shebang(
        host_command,
        preferred_dirs=preferred_interpreter_dirs,
    )
    if env_interpreter is not None and env_interpreter.parent != host_command.parent:
        mounts.append(
            {
                "destination": f"{container_bin_dir}/{env_interpreter.name}",
                "type": "bind",
                "source": str(env_interpreter),
                "options": ["bind", "ro"],
            }
        )
    shell_wrapper_node = resolve_node_for_shell_wrapper(
        host_command,
        preferred_dirs=preferred_interpreter_dirs,
    )
    if shell_wrapper_node is not None and shell_wrapper_node.parent != host_command.parent:
        mounts.append(
            {
                "destination": f"{container_bin_dir}/node",
                "type": "bind",
                "source": str(shell_wrapper_node),
                "options": ["bind", "ro"],
            }
        )

    config_mount = resolve_config_mount(Path(command).name, runtime_home_dir)
    if config_mount is not None:
        mounts.append(config_mount)

    return [container_command, *agent_argv[1:]], mounts


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


def read_log_tail(log_path: Path, max_chars: int = 4000) -> str:
    try:
        text = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return f"<could not read {log_path}: {exc}>"
    if len(text) <= max_chars:
        return text
    return text[-max_chars:]


def wait_for_tcp_ready(
    host: str,
    port: int,
    timeout: float,
    child: subprocess.Popen[bytes] | None = None,
    log_path: Path | None = None,
    service_name: str = "service",
) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if child is not None and child.poll() is not None:
            message = f"{service_name} exited before becoming ready on {host}:{port} (exit {child.returncode})"
            if log_path is not None:
                message += f"\n\nLast log output from {log_path}:\n{read_log_tail(log_path).rstrip()}"
            raise RuntimeError(message)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.settimeout(1)
            sock.connect((host, port))
            return
        except OSError:
            time.sleep(0.2)
        finally:
            sock.close()
    message = f"{service_name} did not become ready on {host}:{port}"
    if log_path is not None:
        message += f"\n\nLast log output from {log_path}:\n{read_log_tail(log_path).rstrip()}"
    raise RuntimeError(message)


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
    reason_pipeline_dir: Path | None = None,
    reason_pipeline_agent_name: str | None = None,
    reason_pipeline_event_dir: Path | None = None,
    reason_pipeline_output_dir: Path | None = None,
    reason_pipeline_log_path: Path | None = None,
    reason_pipeline_db_path: Path | None = None,
    reason_pipeline_max_concurrency: int = 1,
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
    if reason_pipeline_dir is not None:
        command.extend(
            [
                "--reason-pipeline-dir",
                str(reason_pipeline_dir),
                "--reason-pipeline-agent-name",
                reason_pipeline_agent_name or "agent",
                "--reason-pipeline-event-dir",
                str(reason_pipeline_event_dir),
                "--reason-pipeline-output-dir",
                str(reason_pipeline_output_dir),
                "--reason-pipeline-log-path",
                str(reason_pipeline_log_path),
            ]
        )
        if reason_pipeline_db_path is not None:
            command.extend(["--reason-pipeline-db-path", str(reason_pipeline_db_path)])
        command.extend(["--reason-pipeline-max-concurrency", str(reason_pipeline_max_concurrency)])
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
    mitmdump_command: list[str],
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
    mitmdump_args = [
        *mitmdump_command,
        "--listen-host",
        "127.0.0.1",
        "--listen-port",
        str(listen_port),
        "--set",
        "block_global=false",
        "--set",
        "termlog_verbosity=warn",
    ]
    ignore_hosts = os.environ.get("GVISOR_HOOK_MITM_IGNORE_HOSTS", "")
    ignore_hosts_set = [host.strip() for host in ignore_hosts.split(",") if host.strip()]
    if ignore_hosts_set:
        ignore_hosts_pattern = "|".join(re.escape(host) for host in ignore_hosts_set)
        mitmdump_args.extend(["--ignore-hosts", f"^(?:{ignore_hosts_pattern})(?::\\d+)?$"])
    mitmdump_args.extend(["-s", str(addon_path)])
    mitm_log = log_path.open("a", encoding="utf-8")
    return subprocess.Popen(
        mitmdump_args,
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



def resolve_dataset_root(dataset_root: str | None) -> Path:
    if dataset_root:
        return Path(dataset_root).expanduser().resolve()
    return default_dataset_root()


def agent_command_name(agent_argv: list[str]) -> str:
    if not agent_argv:
        return "agent"
    command_name = Path(agent_argv[0]).name
    if command_name in {"python", "python3", "node", "nodejs"} and len(agent_argv) > 1:
        return Path(agent_argv[1]).name
    return command_name or "agent"


def launch(args: argparse.Namespace) -> int:
    workdir = Path(args.workdir).resolve()
    if not workdir.is_dir():
        raise FileNotFoundError(f"workdir does not exist: {workdir}")

    agent_argv: list[str] | None = None
    raw_agent_cmd = getattr(args, "agent_cmd", None)
    if raw_agent_cmd:
        agent_argv = shlex.split(raw_agent_cmd)
    else:
        prompt = getattr(args, "prompt", None)
        if not prompt:
            raise ValueError('Provide --agent-cmd or --prompt (for default "codex exec" mode).')
        agent_argv = [
            "codex",
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

    agent_name = agent_command_name(agent_argv)
    container_id = f"{agent_name}-{int(time.time())}"
    runtime_home_dir = "/tmp/agent-home"
    hook_timeout_ms = max(int(args.decision_timeout * 1000), MIN_HOOK_TIMEOUT_MS)
    hook_enable_after_unix_nano = time.time_ns() + (HOOK_WARMUP_MS * 1_000_000)
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
            "agent_command": agent_name,
            "agent_argv": agent_argv,
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
    reason_pipeline_dir = None
    if not getattr(args, "no_reason_pipeline", False):
        configured_pipeline_dir = getattr(args, "reason_pipeline_dir", None)
        if configured_pipeline_dir:
            reason_pipeline_dir = Path(configured_pipeline_dir).expanduser().resolve()
        else:
            reason_pipeline_dir = default_reason_pipeline_dir(Path(__file__).resolve().parent.parent)
    reason_pipeline_event_dir = dataset_session.session_root / "reason-pipeline-events"
    reason_pipeline_output_dir = model_learning_cap_reason_results_dir(Path(__file__).resolve().parent.parent)
    reason_pipeline_log_path = dataset_session.session_root / "reason-pipeline.ndjson"
    reason_pipeline_db_path = dataset_session.session_root / "reason-pipeline.db"
    host_ip = discover_host_ip()
    broker_tcp_port = reserve_tcp_port()
    mitm_tcp_port = reserve_tcp_port()
    runsc_bin = Path(args.runsc_bin).resolve() if args.runsc_bin else find_runsc_binary()
    mitmdump_command = find_mitmdump_command()
    broker_proc = None
    mitm_proc = None
    runsc_proc = None
    console_server = None
    try:
        proxy_mode = getattr(args, "proxy_mode", "all")
        mitm_proc = spawn_mitmdump(
            mitmdump_command,
            mitm_tcp_port,
            mitm_log_path,
            llm_log_path,
            dataset_session,
        )
        wait_for_tcp_ready(
            "127.0.0.1",
            mitm_tcp_port,
            timeout=10,
            child=mitm_proc,
            log_path=mitm_log_path,
            service_name="mitmdump",
        )
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
            reason_pipeline_dir=reason_pipeline_dir,
            reason_pipeline_agent_name=agent_name,
            reason_pipeline_event_dir=reason_pipeline_event_dir,
            reason_pipeline_output_dir=reason_pipeline_output_dir,
            reason_pipeline_log_path=reason_pipeline_log_path,
            reason_pipeline_db_path=reason_pipeline_db_path,
            reason_pipeline_max_concurrency=args.reason_pipeline_max_concurrency,
        )
        wait_for_http_ready(args.web_port, timeout=10)
        resolv_path, hosts_path, nsswitch_path = write_runtime_network_files(runtime_dir)
        upstream_proxy_url = f"http://127.0.0.1:{mitm_tcp_port}"
        sandbox_upstream_proxy_url = upstream_proxy_url if proxy_mode == "all" else None
        mitm_ca_cert = None
        trusted_ca_cert_path = None
        if proxy_mode == "all":
            # Always try to mount the mitmproxy CA cert so HTTPS traffic can be
            # TLS-intercepted. Without this, mitmproxy sees an encrypted tunnel
            # but cannot read the request body, so no LLM logs are produced.
            with suppress(FileNotFoundError):
                mitm_ca_cert = find_mitmproxy_ca_cert()
                trusted_ca_cert_path = "/tmp/mitmproxy/mitmproxy-ca-cert.pem"

        agent_argv, agent_mounts = resolve_agent_argv_and_mounts(agent_argv, runtime_home_dir)
        if mitm_ca_cert is not None and trusted_ca_cert_path:
            # Copy only the CA cert into a staging directory and bind-mount the
            # directory (not the file) into the container.  gVisor requires the
            # bind-mount destination to pre-exist; a file target under /tmp (which
            # is a tmpfs) may not exist yet, causing a silent mount failure.
            # Mounting the parent directory avoids that problem.
            certs_staging = runtime_dir / "certs"
            certs_staging.mkdir(exist_ok=True)
            shutil.copy2(str(mitm_ca_cert), str(certs_staging / mitm_ca_cert.name))
            agent_mounts.append(
                {
                    "destination": str(Path(trusted_ca_cert_path).parent),
                    "type": "bind",
                    "source": str(certs_staging),
                    "options": ["rbind", "ro"],
                }
            )
        write_bundle_config(
            bundle_dir,
            workdir=workdir,
            runtime_home_dir=runtime_home_dir,
            container_id=container_id,
            resolv_conf_path=str(resolv_path),
            hosts_path=str(hosts_path),
            nsswitch_conf_path=str(nsswitch_path),
            upstream_proxy_url=sandbox_upstream_proxy_url,
            agent_argv=agent_argv,
            extra_mounts=agent_mounts,
            trusted_ca_cert_path=trusted_ca_cert_path,
            hook_timeout_ms=hook_timeout_ms,
            hook_warmup_ms=HOOK_WARMUP_MS,
            hook_enable_after_unix_nano=hook_enable_after_unix_nano,
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
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        console_server = ConsoleSocketServer(console_socket_path)

        env = os.environ.copy()
        env.update(
            {
                "GVISOR_HOOK_ADDR": f"127.0.0.1:{broker_tcp_port}",
                "GVISOR_HOOK_TIMEOUT_MS": str(hook_timeout_ms),
                "GVISOR_HOOK_WARMUP_MS": str(HOOK_WARMUP_MS),
                "GVISOR_HOOK_ENABLE_AFTER_UNIX_NANO": str(hook_enable_after_unix_nano),
                "GVISOR_HOOK_CONTAINER_ID": container_id,
            }
        )

        print(f"Approval UI: http://127.0.0.1:{args.web_port}", file=sys.stderr)
        if proxy_mode == "all":
            print(f"HTTP(S) proxy (mitm): {upstream_proxy_url}", file=sys.stderr)
            if trusted_ca_cert_path:
                print(f"Trusted mitm CA: {trusted_ca_cert_path}", file=sys.stderr)
            else:
                print("Warning: mitmproxy CA cert not found; HTTPS interception may fail", file=sys.stderr)
        else:
            print("HTTP(S) proxy (mitm): disabled", file=sys.stderr)
        print(f"Dataset session: {dataset_session.session_root}", file=sys.stderr)
        if reason_pipeline_dir is not None:
            print(f"Reason pipeline: {reason_pipeline_dir}", file=sys.stderr)
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
        time.sleep(HOOK_WARMUP_MS / 1000)
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
