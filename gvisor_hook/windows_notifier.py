from __future__ import annotations

import logging
import shutil
import subprocess
from pathlib import Path

LOG = logging.getLogger(__name__)


def _windows_path(path: Path) -> str:
    wslpath = shutil.which("wslpath")
    if not wslpath:
        return str(path)
    result = subprocess.run(
        [wslpath, "-w", str(path)],
        capture_output=True,
        text=True,
        timeout=5,
    )
    if result.returncode != 0:
        LOG.warning("wslpath failed for %s: %s", path, result.stderr.strip())
        return str(path)
    return result.stdout.strip() or str(path)


def spawn_windows_approval_notifier(
    *,
    broker_url: str,
    approval_url: str | None = None,
    site_window_title: str | None = None,
) -> subprocess.Popen[bytes] | None:
    powershell = shutil.which("powershell.exe")
    if not powershell:
        LOG.info("Windows approval notifier disabled: powershell.exe was not found")
        return None

    script_path = Path(__file__).resolve().parent.parent / "scripts" / "windows_approval_notifier.ps1"
    if not script_path.is_file():
        LOG.warning("Windows approval notifier script was not found: %s", script_path)
        return None

    broker_url = broker_url.rstrip("/")
    approval_url = (approval_url or broker_url).rstrip("/")
    command = [
        powershell,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-Sta",
        "-WindowStyle",
        "Hidden",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        _windows_path(script_path),
        "-BrokerUrl",
        broker_url,
        "-ApprovalUrl",
        approval_url,
    ]
    if site_window_title:
        command.extend(["-SiteWindowTitle", site_window_title])

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except OSError:
        LOG.exception("Failed to start the Windows approval notifier")
        return None

    LOG.info(
        "Started Windows approval notifier pid=%s broker=%s",
        process.pid,
        broker_url,
    )
    return process
