from __future__ import annotations

import asyncio
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .dataset import append_ndjson, safe_slug, utc_now
from .models import LLMExchange, SyscallEvent


@dataclass(frozen=True, slots=True)
class ReasonPipelineConfig:
    pipeline_dir: Path
    agent_name: str
    event_dir: Path
    output_dir: Path
    log_path: Path
    db_path: Path | None = None
    max_concurrency: int = 1


@dataclass(frozen=True, slots=True)
class ReasonPipelineReplayResult:
    session_root: Path
    event_count: int
    success_count: int
    failure_count: int
    log_path: Path
    output_dir: Path


def default_reason_pipeline_dir(repo_root: Path) -> Path | None:
    candidate = repo_root / "third_party" / "reason_pipeline"
    if (candidate / "pipeline.py").is_file():
        return candidate.resolve()
    return None


def reason_pipeline_python(pipeline_dir: Path) -> Path:
    candidate = pipeline_dir / "venv" / "bin" / "python"
    if candidate.is_file():
        return candidate
    return Path(sys.executable)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_json_file(path: str | None) -> Any:
    if not path:
        return {}
    candidate = Path(path)
    if not candidate.is_file():
        return {}
    try:
        return json.loads(candidate.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return {}


def exchange_payload(exchange: LLMExchange | None) -> tuple[Any, Any]:
    if exchange is None:
        return {}, {}
    request_payload = load_json_file(exchange.request_body_path) or exchange.request_body or {}
    response_payload = load_json_file(exchange.response_body_path) or exchange.response_body or {}
    return request_payload, response_payload


def build_pipeline_event(
    *,
    agent_name: str,
    exchange: LLMExchange | None,
    syscall_event: SyscallEvent,
) -> dict[str, Any]:
    request_payload, response_payload = exchange_payload(exchange)
    syscall_payload = syscall_event.to_dict()
    syscall_payload.setdefault("name", syscall_event.syscall)
    return {
        "agent_name": agent_name,
        "request": request_payload,
        "response": response_payload,
        "syscall": syscall_payload,
    }


def write_pipeline_event(
    config: ReasonPipelineConfig,
    *,
    exchange: LLMExchange | None,
    syscall_event: SyscallEvent,
) -> Path:
    config.event_dir.mkdir(parents=True, exist_ok=True)
    event_path = config.event_dir / f"{safe_slug(syscall_event.id)}.json"
    event = build_pipeline_event(
        agent_name=config.agent_name,
        exchange=exchange,
        syscall_event=syscall_event,
    )
    event_path.write_text(json.dumps(event, ensure_ascii=False, indent=2), encoding="utf-8")
    return event_path


async def run_reason_pipeline_event(
    config: ReasonPipelineConfig,
    *,
    exchange: LLMExchange | None,
    syscall_event: SyscallEvent,
) -> dict[str, Any]:
    event_path = write_pipeline_event(config, exchange=exchange, syscall_event=syscall_event)
    command = [
        str(reason_pipeline_python(config.pipeline_dir)),
        str(config.pipeline_dir / "pipeline.py"),
        "--event-file",
        str(event_path),
    ]
    if config.db_path is not None:
        command.extend(["--db-path", str(config.db_path)])
    command.extend(["--event-output-dir", str(config.output_dir)])

    started_at = utc_now()
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(config.pipeline_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    completed_at = utc_now()
    record: dict[str, Any] = {
        "type": "reason-pipeline-run",
        "payload": {
            "event_id": syscall_event.id,
            "syscall": syscall_event.syscall,
            "agent_name": config.agent_name,
            "event_path": str(event_path),
            "command": command,
            "returncode": proc.returncode,
            "started_at": started_at,
            "completed_at": completed_at,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        },
    }
    append_ndjson(config.log_path, record)
    return record


def reason_pipeline_event_sort_key(path: Path) -> tuple[str, int, str]:
    stem = path.stem
    prefix, sep, suffix = stem.rpartition("-")
    if sep and suffix.isdigit():
        return (prefix, int(suffix), stem)
    return (stem, -1, stem)


async def replay_reason_pipeline_session(
    session_root: Path,
    *,
    pipeline_dir: Path | None = None,
    clear_results: bool = False,
) -> ReasonPipelineReplayResult:
    session_root = session_root.expanduser().resolve()
    if not session_root.is_dir():
        raise FileNotFoundError(f"session directory not found: {session_root}")

    resolved_pipeline_dir = pipeline_dir
    if resolved_pipeline_dir is None:
        resolved_pipeline_dir = default_reason_pipeline_dir(repo_root())
    if resolved_pipeline_dir is None:
        raise FileNotFoundError("reason pipeline was not found at third_party/reason_pipeline")
    resolved_pipeline_dir = resolved_pipeline_dir.expanduser().resolve()

    event_dir = session_root / "reason-pipeline-events"
    output_dir = session_root / "reason-pipeline-results"
    log_path = session_root / "reason-pipeline-replay.ndjson"
    db_path = session_root / "reason-pipeline.db"
    if not event_dir.is_dir():
        raise FileNotFoundError(f"reason pipeline event directory not found: {event_dir}")
    if clear_results and output_dir.exists():
        for result_path in output_dir.glob("*.json"):
            result_path.unlink()
    output_dir.mkdir(parents=True, exist_ok=True)

    event_paths = sorted(event_dir.glob("*.json"), key=reason_pipeline_event_sort_key)
    success_count = 0
    failure_count = 0
    for event_path in event_paths:
        record = await run_reason_pipeline_event_file(
            pipeline_dir=resolved_pipeline_dir,
            event_path=event_path,
            output_dir=output_dir,
            log_path=log_path,
            db_path=db_path,
        )
        if record["payload"]["returncode"] == 0:
            success_count += 1
        else:
            failure_count += 1

    return ReasonPipelineReplayResult(
        session_root=session_root,
        event_count=len(event_paths),
        success_count=success_count,
        failure_count=failure_count,
        log_path=log_path,
        output_dir=output_dir,
    )


async def run_reason_pipeline_event_file(
    *,
    pipeline_dir: Path,
    event_path: Path,
    output_dir: Path,
    log_path: Path,
    db_path: Path | None,
) -> dict[str, Any]:
    command = [
        str(reason_pipeline_python(pipeline_dir)),
        str(pipeline_dir / "pipeline.py"),
        "--event-file",
        str(event_path),
        "--event-output-dir",
        str(output_dir),
    ]
    if db_path is not None:
        command.extend(["--db-path", str(db_path)])

    started_at = utc_now()
    proc = await asyncio.create_subprocess_exec(
        *command,
        cwd=str(pipeline_dir),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    completed_at = utc_now()
    event_id = event_path.stem
    try:
        event_payload = json.loads(event_path.read_text(encoding="utf-8-sig"))
        syscall_payload = event_payload.get("syscall", {})
        syscall_name = syscall_payload.get("name") or syscall_payload.get("syscall")
        agent_name = event_payload.get("agent_name")
    except (OSError, json.JSONDecodeError, AttributeError):
        syscall_name = None
        agent_name = None
    record: dict[str, Any] = {
        "type": "reason-pipeline-replay-run",
        "payload": {
            "event_id": event_id,
            "syscall": syscall_name,
            "agent_name": agent_name,
            "event_path": str(event_path),
            "output_dir": str(output_dir),
            "command": command,
            "returncode": proc.returncode,
            "started_at": started_at,
            "completed_at": completed_at,
            "stdout": stdout.decode("utf-8", errors="replace"),
            "stderr": stderr.decode("utf-8", errors="replace"),
        },
    }
    append_ndjson(log_path, record)
    return record
