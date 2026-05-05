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
    log_path: Path
    db_path: Path | None = None


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
