from __future__ import annotations

import json
import os
from pathlib import Path


DEFAULT_ENV_ALLOWLIST_PREFIXES = (
    "OPENAI_",
    "ANTHROPIC_",
    "GEMINI_",
    "GOOGLE_",
    "AZURE_",
    "AWS_",
    "MISTRAL_",
    "TOGETHER_",
    "DEEPSEEK_",
    "XAI_",
    "OLLAMA_",
    "LITELLM_",
)


def build_process_env(
    home_dir: str,
    proxy_base_url: str,
    *,
    agent_bin_dir: str,
    python_path_entries: list[str] | None = None,
    hook_addr: str | None = None,
    hook_socket_path: str | None = None,
    hook_event_log_path: str | None = None,
    hook_decision_dir: str | None = None,
    hook_timeout_ms: int | None = None,
    hook_warmup_ms: int | None = None,
    hook_container_id: str | None = None,
) -> list[str]:
    env = {
        "HOME": home_dir,
        "XDG_CACHE_HOME": f"{home_dir}/.cache",
        "XDG_CONFIG_HOME": f"{home_dir}/.config",
        "PYTHONUNBUFFERED": "1",
        "OPENAI_BASE_URL": proxy_base_url,
        "OPENAI_API_BASE": proxy_base_url,
        "LITELLM_LOCAL_MODEL_COST_MAP": "true",
        "TERM": os.environ.get("TERM", "xterm-256color"),
        "COLORTERM": os.environ.get("COLORTERM", "truecolor"),
        "PATH": f"{agent_bin_dir}:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": os.environ.get("LANG", "C.UTF-8"),
    }
    python_path = ["/tmp/bootstrap"]
    if python_path_entries:
        python_path.extend(python_path_entries)
    env["PYTHONPATH"] = ":".join(python_path)
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
        if key.endswith("_API_KEY") or key.startswith(DEFAULT_ENV_ALLOWLIST_PREFIXES):
            env[key] = value
    return [f"{key}={value}" for key, value in sorted(env.items()) if value]


def write_bundle_config(
    bundle_dir: Path,
    *,
    workdir: Path,
    runtime_home_dir: str,
    container_id: str,
    process_args: list[str],
    agent_bin_dir: str,
    extra_mounts: list[dict[str, object]],
    python_path_entries: list[str] | None = None,
    resolv_conf_path: str,
    hosts_path: str,
    nsswitch_conf_path: str,
    proxy_base_url: str,
    hook_addr: str | None = None,
    hook_socket_path: str | None = None,
    hook_event_log_path: str | None = None,
    hook_decision_dir: str | None = None,
    hook_timeout_ms: int | None = None,
    hook_warmup_ms: int | None = None,
    hook_container_id: str | None = None,
) -> Path:
    bundle_dir.mkdir(parents=True, exist_ok=True)
    (bundle_dir / "rootfs").mkdir(exist_ok=True)
    workdir = workdir.resolve()

    config = {
        "ociVersion": "1.0.2",
        "process": {
            "terminal": True,
            "user": {"uid": 0, "gid": 0},
            "args": process_args,
            "cwd": "/tmp/workspace",
            "env": build_process_env(
                runtime_home_dir,
                proxy_base_url,
                agent_bin_dir=agent_bin_dir,
                python_path_entries=python_path_entries,
                hook_addr=hook_addr,
                hook_socket_path=hook_socket_path,
                hook_event_log_path=hook_event_log_path,
                hook_decision_dir=hook_decision_dir,
                hook_timeout_ms=hook_timeout_ms,
                hook_warmup_ms=hook_warmup_ms,
                hook_container_id=hook_container_id,
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
            {"destination": "/etc/resolv.conf", "type": "bind", "source": resolv_conf_path, "options": ["bind", "ro"]},
            {"destination": "/etc/hosts", "type": "bind", "source": hosts_path, "options": ["bind", "ro"]},
            {"destination": "/etc/nsswitch.conf", "type": "bind", "source": nsswitch_conf_path, "options": ["bind", "ro"]},
            {"destination": "/tmp/workspace", "type": "bind", "source": str(workdir), "options": ["rbind", "rw"]},
            *extra_mounts,
        ],
        "linux": {
            "namespaces": [
                {"type": "pid"},
                {"type": "ipc"},
                {"type": "uts"},
                {"type": "mount"},
                {"type": "network"},
            ]
        },
    }

    config_path = bundle_dir / "config.json"
    config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    return config_path
