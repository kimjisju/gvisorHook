from __future__ import annotations

import hashlib
import json
import string
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


DATASET_ROOT_NAME = "datasets/raw-response-dataset"
TEXT_PREVIEW_LIMIT = 4096


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def project_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_dataset_root() -> Path:
    return project_root() / DATASET_ROOT_NAME


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def write_json(path: Path, payload: dict[str, Any]) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def append_ndjson(path: Path, payload: dict[str, Any]) -> None:
    ensure_parent(path)
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(payload, ensure_ascii=False) + "\n")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def safe_slug(value: str) -> str:
    allowed = set(string.ascii_letters + string.digits + "-_.")
    sanitized = "".join(ch if ch in allowed else "-" for ch in value)
    sanitized = sanitized.strip("-.")
    return sanitized or "item"


def make_session_id(prefix: str = "session") -> str:
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    return f"{timestamp}-{safe_slug(prefix)}"


def relative_path(path: Path, base: Path) -> str:
    try:
        return str(path.relative_to(base))
    except ValueError:
        return str(path)


def bytes_preview(data: bytes | None, *, limit: int = TEXT_PREVIEW_LIMIT) -> str | None:
    if data is None:
        return None
    if not data:
        return ""
    sample = data[:limit]
    has_nul = b"\x00" in sample
    try:
        decoded = sample.decode("utf-8")
    except UnicodeDecodeError:
        decoded = sample.decode("utf-8", errors="replace")
    printable = sum(1 for ch in decoded if ch.isprintable() or ch in "\r\n\t")
    ratio = printable / max(len(decoded), 1)
    if has_nul or ratio < 0.85:
        return f"<binary {len(data)} bytes sha256={sha256_hex(data)}>"
    if len(data) > limit:
        return decoded + "\n...<truncated preview>..."
    return decoded


def header_block(start_line: str, header_fields: Iterable[tuple[bytes, bytes]]) -> bytes:
    lines = [start_line.encode("utf-8")]
    for key, value in header_fields:
        lines.append(key + b": " + value)
    return b"\r\n".join(lines) + b"\r\n\r\n"


def append_binary(path: Path, data: bytes) -> int:
    ensure_parent(path)
    with path.open("ab") as fh:
        offset = fh.tell()
        fh.write(data)
    return offset


@dataclass(frozen=True, slots=True)
class DatasetSessionPaths:
    dataset_root: Path
    session_id: str
    session_root: Path
    agent_dir: Path
    llm_dir: Path
    manifest_path: Path
    session_index_path: Path
    terminal_log_path: Path
    terminal_stdin_path: Path
    terminal_stdout_path: Path
    llm_ui_log_path: Path
    broker_log_path: Path
    mitm_log_path: Path


def create_dataset_session(
    dataset_root: Path,
    session_id: str,
    metadata: dict[str, Any],
) -> DatasetSessionPaths:
    session_root = dataset_root / "sessions" / session_id
    agent_dir = session_root / "agent"
    llm_dir = session_root / "llm"
    paths = DatasetSessionPaths(
        dataset_root=dataset_root,
        session_id=session_id,
        session_root=session_root,
        agent_dir=agent_dir,
        llm_dir=llm_dir,
        manifest_path=session_root / "manifest.json",
        session_index_path=session_root / "index.ndjson",
        terminal_log_path=agent_dir / "terminal.ndjson",
        terminal_stdin_path=agent_dir / "stdin.bin",
        terminal_stdout_path=agent_dir / "stdout.bin",
        llm_ui_log_path=llm_dir / "ui.ndjson",
        broker_log_path=session_root / "broker.log",
        mitm_log_path=session_root / "mitmproxy.log",
    )
    paths.agent_dir.mkdir(parents=True, exist_ok=True)
    paths.llm_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "session_id": session_id,
        "created_at": utc_now(),
        "dataset_root": str(dataset_root),
        "session_root": str(session_root),
        "agent": {
            "terminal_log_path": str(paths.terminal_log_path),
            "stdin_path": str(paths.terminal_stdin_path),
            "stdout_path": str(paths.terminal_stdout_path),
        },
        "llm": {
            "ui_log_path": str(paths.llm_ui_log_path),
            "llm_root": str(paths.llm_dir),
        },
        "logs": {
            "broker_log_path": str(paths.broker_log_path),
            "mitm_log_path": str(paths.mitm_log_path),
        },
        "metadata": metadata,
    }
    write_json(paths.manifest_path, manifest)
    append_ndjson(
        dataset_root / "sessions.ndjson",
        {
            "type": "session-created",
            "payload": {
                "session_id": session_id,
                "created_at": manifest["created_at"],
                "session_root": str(session_root),
                "metadata": metadata,
            },
        },
    )
    append_ndjson(
        paths.session_index_path,
        {
            "type": "session-created",
            "payload": {
                "session_id": session_id,
                "created_at": manifest["created_at"],
            },
        },
    )
    return paths


def dataset_session_from_root(session_root: Path) -> DatasetSessionPaths:
    dataset_root = session_root.parent.parent
    session_id = session_root.name
    return DatasetSessionPaths(
        dataset_root=dataset_root,
        session_id=session_id,
        session_root=session_root,
        agent_dir=session_root / "agent",
        llm_dir=session_root / "llm",
        manifest_path=session_root / "manifest.json",
        session_index_path=session_root / "index.ndjson",
        terminal_log_path=session_root / "agent" / "terminal.ndjson",
        terminal_stdin_path=session_root / "agent" / "stdin.bin",
        terminal_stdout_path=session_root / "agent" / "stdout.bin",
        llm_ui_log_path=session_root / "llm" / "ui.ndjson",
        broker_log_path=session_root / "broker.log",
        mitm_log_path=session_root / "mitmproxy.log",
    )


def record_terminal_chunk(
    session: DatasetSessionPaths,
    *,
    stream: str,
    data: bytes,
    timestamp: str | None = None,
) -> dict[str, Any]:
    if stream not in {"stdin", "stdout"}:
        raise ValueError(f"unsupported terminal stream: {stream}")
    target = session.terminal_stdin_path if stream == "stdin" else session.terminal_stdout_path
    offset = append_binary(target, data)
    payload = {
        "stream": stream,
        "timestamp": timestamp or utc_now(),
        "offset": offset,
        "length": len(data),
        "path": str(target),
        "sha256": sha256_hex(data),
    }
    append_ndjson(session.terminal_log_path, payload)
    append_ndjson(
        session.session_index_path,
        {
            "type": "terminal-chunk",
            "payload": payload,
        },
    )
    return payload


def flow_artifact_dir(session: DatasetSessionPaths, flow_id: str) -> Path:
    return session.llm_dir / safe_slug(flow_id)


def flow_artifact_paths(session: DatasetSessionPaths, flow_id: str) -> dict[str, Path]:
    flow_dir = flow_artifact_dir(session, flow_id)
    flow_dir.mkdir(parents=True, exist_ok=True)
    return {
        "flow_dir": flow_dir,
        "request_headers_path": flow_dir / "request_headers.raw",
        "request_body_path": flow_dir / "request_body.bin",
        "response_headers_path": flow_dir / "response_headers.raw",
        "response_body_path": flow_dir / "response_body.bin",
        "meta_path": flow_dir / "meta.json",
    }
