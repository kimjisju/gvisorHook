from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .db import PipelineDatabase, SyscallImpact
from .parser_manager import ParserManager
from .schema import extract_syscall_name, slugify


@dataclass
class PipelineResult:
    status: str
    syscall_name: str
    affects_host_os: int
    reason: str
    event_id: str | None = None
    event_path: str | None = None
    agent_name: str | None = None
    prompt_text: str | None = None
    reasoning_text: str | None = None
    parser_path: str | None = None
    schema_signature: str | None = None
    parser_source: str | None = None


class SyscallNormalizationPipeline:
    def __init__(
        self,
        *,
        base_dir: Path | None = None,
        db_path: Path | None = None,
        mapping_csv_path: Path | None = None,
        parser_dir: Path | None = None,
        event_output_dir: Path | None = None,
    ) -> None:
        resolved_base_dir = base_dir or Path(__file__).resolve().parent.parent
        resolved_db_path = db_path or resolved_base_dir / "data" / "pipeline.db"
        resolved_mapping_path = mapping_csv_path or resolved_base_dir / "data" / "syscall_host_impact_map.csv"
        resolved_parser_dir = parser_dir or resolved_base_dir / "generated_parsers"
        self.event_output_dir = event_output_dir or resolved_base_dir / "data" / "events"

        self.database = PipelineDatabase(resolved_db_path, resolved_mapping_path)
        self.database.initialize()
        self.parser_manager = ParserManager(self.database, resolved_parser_dir)

    def process_event(
        self,
        *,
        agent_name: str,
        request_payload: Any,
        response_payload: Any,
        syscall_payload: Any,
    ) -> PipelineResult:
        syscall_name = extract_syscall_name(syscall_payload)
        syscall_impact = self.database.lookup_syscall(syscall_name)

        if syscall_impact.affects_host_os == 0:
            event_id, event_path = self._write_event_json(
                status="skipped",
                agent_name=agent_name,
                syscall_impact=syscall_impact,
                request_payload=request_payload,
                response_payload=response_payload,
                syscall_payload=syscall_payload,
                prompt_text="",
                reasoning_text="",
                parser_path=None,
                schema_signature=None,
                parser_source=None,
            )
            return PipelineResult(
                status="skipped",
                syscall_name=syscall_impact.syscall_name,
                affects_host_os=0,
                reason=self._format_skip_reason(syscall_impact),
                event_id=event_id,
                event_path=str(event_path),
                agent_name=agent_name,
            )

        parser_result = self.parser_manager.resolve(
            agent_name=agent_name,
            request_payload=request_payload,
            response_payload=response_payload,
        )
        event_id, event_path = self._write_event_json(
            status="stored",
            agent_name=agent_name,
            syscall_impact=syscall_impact,
            request_payload=request_payload,
            response_payload=response_payload,
            syscall_payload=syscall_payload,
            prompt_text=parser_result.prompt_text,
            reasoning_text=parser_result.reasoning_text,
            parser_path=str(parser_result.parser_path),
            schema_signature=parser_result.schema_signature,
            parser_source=parser_result.source,
        )
        return PipelineResult(
            status="stored",
            syscall_name=syscall_impact.syscall_name,
            affects_host_os=syscall_impact.affects_host_os,
            reason=syscall_impact.rationale,
            event_id=event_id,
            event_path=str(event_path),
            agent_name=agent_name,
            prompt_text=parser_result.prompt_text,
            reasoning_text=parser_result.reasoning_text,
            parser_path=str(parser_result.parser_path),
            schema_signature=parser_result.schema_signature,
            parser_source=parser_result.source,
        )

    def _write_event_json(
        self,
        *,
        status: str,
        agent_name: str,
        syscall_impact: SyscallImpact,
        request_payload: Any,
        response_payload: Any,
        syscall_payload: Any,
        prompt_text: str,
        reasoning_text: str,
        parser_path: str | None,
        schema_signature: str | None,
        parser_source: str | None,
    ) -> tuple[str, Path]:
        self.event_output_dir.mkdir(parents=True, exist_ok=True)
        timestamp = datetime.now(timezone.utc).isoformat()
        event_id = self._event_id(syscall_payload, syscall_impact.syscall_name, timestamp)
        event_path = self.event_output_dir / f"{event_id}.json"
        counter = 1
        while event_path.exists():
            counter += 1
            event_path = self.event_output_dir / f"{event_id}-{counter}.json"
        payload = {
            "event_id": event_path.stem,
            "status": status,
            "agent_name": agent_name,
            "syscall_name": syscall_impact.syscall_name,
            "affects_host_os": syscall_impact.affects_host_os,
            "syscall_category": syscall_impact.category,
            "reason": syscall_impact.rationale,
            "syscall_mapping_source": syscall_impact.source,
            "is_known_syscall": syscall_impact.is_known,
            "prompt_text": prompt_text,
            "reasoning_text": reasoning_text,
            "schema_signature": schema_signature,
            "parser_source": parser_source,
            "parser_path": parser_path,
            "request": request_payload,
            "response": response_payload,
            "syscall": syscall_payload,
            "created_at": timestamp,
        }
        event_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return event_path.stem, event_path

    def _event_id(self, syscall_payload: Any, syscall_name: str, timestamp: str) -> str:
        candidate = None
        if isinstance(syscall_payload, dict):
            raw_id = syscall_payload.get("id") or syscall_payload.get("event_id")
            if isinstance(raw_id, str) and raw_id.strip():
                candidate = raw_id
        if candidate is None:
            compact_timestamp = timestamp.replace("+00:00", "Z").replace(":", "").replace(".", "")
            candidate = f"{compact_timestamp}-{syscall_name}"
        return slugify(str(candidate)).replace("_", "-")

    def _format_skip_reason(self, syscall_impact: SyscallImpact) -> str:
        return (
            f"syscall '{syscall_impact.syscall_name}' is marked as non-host-impacting "
            f"({syscall_impact.category}): {syscall_impact.rationale}"
        )
