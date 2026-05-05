from __future__ import annotations

import json
import os
from pathlib import Path


DEFAULT_ENV_ALLOWLIST_SUFFIXES = (
    "_API_KEY",
    "_API_BASE",
    "_ACCESS_TOKEN",
    "_AUTH_TOKEN",
    "_BASE_URL",
    "_BEARER_TOKEN",
    "_CREDENTIALS",
    "_CREDENTIALS_FILE",
    "_ENDPOINT",
)

LOCAL_PROXY_BYPASS_HOSTS = (
    "127.0.0.1",
    "localhost",
)


DATASET_PLAN_INSTRUCTIONS = (
    "DATASET CAPTURE MODE: For every non-trivial user request, expose a short visible PLAN section "
    "before taking action. Keep the plan concise, factual, and directly relevant to the task. "
    "Do not hide the plan inside code blocks. After the PLAN, continue normally and complete the task."
)


def build_process_env(
    home_dir: str,
    *,
    upstream_proxy_url: str | None = None,
    hook_addr: str | None = None,
    hook_socket_path: str | None = None,
    hook_event_log_path: str | None = None,
    hook_decision_dir: str | None = None,
    hook_timeout_ms: int | None = None,
    hook_warmup_ms: int | None = None,
    hook_container_id: str | None = None,
    proxy_bypass_hosts: list[str] | tuple[str, ...] | None = None,
    trusted_ca_cert_path: str | None = None,
) -> list[str]:
    bypass_hosts = list(LOCAL_PROXY_BYPASS_HOSTS if proxy_bypass_hosts is None else proxy_bypass_hosts)
    extra_no_proxy = os.environ.get("GVISOR_HOOK_EXTRA_NO_PROXY", "")
    bypass_hosts.extend(host.strip() for host in extra_no_proxy.split(",") if host.strip())
    env = {
        "HOME": home_dir,
        "XDG_CACHE_HOME": f"{home_dir}/.cache",
        "XDG_CONFIG_HOME": f"{home_dir}/.config",
        "PYTHONUNBUFFERED": "1",
        "LITELLM_LOCAL_MODEL_COST_MAP": "true",
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "COLORTERM": os.environ.get("COLORTERM", "truecolor"),
        # Some TUI apps (including Codex) fall back to these when window-size ioctls
        # are unavailable in restricted sandboxes.
        "COLUMNS": os.environ.get("COLUMNS", "120"),
        "LINES": os.environ.get("LINES", "40"),
        #"PATH": "/tmp/open-interpreter/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PATH": "/tmp/agent/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    if upstream_proxy_url:
        no_proxy_val = ",".join(dict.fromkeys(bypass_hosts))
        # Set both uppercase and lowercase variants; different clients (curl, wget,
        # Python requests, Node.js fetch, etc.) read different casing.
        for _k in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"):
            env.setdefault(_k, upstream_proxy_url)
            env.setdefault(_k.lower(), upstream_proxy_url)
        env.setdefault("NO_PROXY", no_proxy_val)
        env.setdefault("no_proxy", no_proxy_val)
    if trusted_ca_cert_path:
        env.setdefault("NODE_EXTRA_CA_CERTS", trusted_ca_cert_path)
        env.setdefault("REQUESTS_CA_BUNDLE", trusted_ca_cert_path)
        env.setdefault("SSL_CERT_FILE", trusted_ca_cert_path)
        env.setdefault("CURL_CA_BUNDLE", trusted_ca_cert_path)
        env.setdefault("GIT_SSL_CAINFO", trusted_ca_cert_path)
        env.setdefault("GRPC_DEFAULT_SSL_ROOTS_FILE_PATH", trusted_ca_cert_path)
    if hook_addr:
        env["GVISOR_HOOK_ADDR"] = hook_addr
    if hook_socket_path:
        env["GVISOR_HOOK_SOCKET"] = hook_socket_path
    if hook_event_log_path:
        env["GVISOR_HOOK_EVENT_LOG"] = hook_event_log_path
    if hook_decision_dir:
        env["GVISOR_HOOK_DECISION_DIR"] = hook_decision_dir
    if hook_timeout_ms is not None:
        env["GVISOR_HOOK_TIMEOUT_MS"] = str(hook_timeout_ms)
    if hook_warmup_ms is not None:
        env["GVISOR_HOOK_WARMUP_MS"] = str(hook_warmup_ms)
    if hook_container_id:
        env["GVISOR_HOOK_CONTAINER_ID"] = hook_container_id
    for key, value in os.environ.items():
        if key.endswith(DEFAULT_ENV_ALLOWLIST_SUFFIXES):
            env[key] = value
    return [f"{key}={value}" for key, value in sorted(env.items()) if value]


def write_bundle_config(
    bundle_dir: Path,
    *,
    workdir: Path,
    runtime_home_dir: str,
    container_id: str,
    resolv_conf_path: str,
    hosts_path: str,
    nsswitch_conf_path: str,
    upstream_proxy_url: str | None = None,
    agent_argv: list[str] | None = None,
    extra_mounts: list[dict[str, object]] | None = None,
    hook_addr: str | None = None,
    hook_socket_path: str | None = None,
    hook_event_log_path: str | None = None,
    hook_decision_dir: str | None = None,
    hook_timeout_ms: int | None = None,
    hook_warmup_ms: int | None = None,
    hook_container_id: str | None = None,
    proxy_bypass_hosts: list[str] | tuple[str, ...] | None = None,
    trusted_ca_cert_path: str | None = None,
    profile: str | None = None,
    custom_instructions: str | None = None,
) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "rootfs").mkdir(exist_ok=True)
    workdir = workdir.resolve()

    process_args = agent_argv or ["/usr/local/bin/codex"]

    config = {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": True,
            "user": {"uid": 0, "gid": 0},
            "args": process_args,
            "cwd": "/tmp/workspace",
            "env": build_process_env(
                runtime_home_dir,
                upstream_proxy_url=upstream_proxy_url,
                hook_addr=hook_addr,
                hook_socket_path=hook_socket_path,
                hook_event_log_path=hook_event_log_path,
                hook_decision_dir=hook_decision_dir,
                hook_timeout_ms=hook_timeout_ms,
                hook_warmup_ms=hook_warmup_ms,
                hook_container_id=hook_container_id,
                proxy_bypass_hosts=proxy_bypass_hosts,
                trusted_ca_cert_path=trusted_ca_cert_path,
            ),
            "capabilities": {
                "bounding": [],
                "effective": [],
                "inheritable": [],
                "permitted": [],
                "ambient": [],
            },
        },
        "root": {"path": "/", "readonly": True},
        "hostname": container_id,
	        "mounts": [
	            {"destination": "/proc", "type": "proc", "source": "proc", "options": ["nosuid", "noexec", "nodev"]},
	            {"destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=1777", "size=268435456"]},
	            {"destination": "/home", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "nodev", "mode=0777", "size=268435456"]},
	            {"destination": "/etc/resolv.conf", "type": "bind", "source": resolv_conf_path, "options": ["bind", "ro"]},
	            {"destination": "/etc/hosts", "type": "bind", "source": hosts_path, "options": ["bind", "ro"]},
	            {"destination": "/etc/nsswitch.conf", "type": "bind", "source": nsswitch_conf_path, "options": ["bind", "ro"]},
	            {"destination": "/tmp/workspace", "type": "bind", "source": str(workdir), "options": ["rbind", "rw"]},
                {"destination": "/usr/bin/git", "type": "bind", "source": "/usr/bin/git", "options": ["bind", "ro"]},
                {"destination": "/usr/bin/getconf", "type": "bind", "source": "/usr/bin/getconf", "options": ["bind", "ro"]},
                {"destination": "/usr/bin/lsb_release", "type": "bind", "source": "/usr/bin/lsb_release", "options": ["bind", "ro"]},
	            #{"destination": "/tmp/open-interpreter/bin/interpreter", "type": "bind", "source": "/home/kimjisu/.local/bin/interpreter", "options": ["bind", "ro"]},
            #{"destination": "/tmp/open-interpreter/site-packages", "type": "bind", "source": "/home/kimjisu/.local/lib/python3.10/site-packages", "options": ["rbind", "ro"]},
                *(extra_mounts or []),
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
            ]
        },
    }

    config_path = bundle_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path
