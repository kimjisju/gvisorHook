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
    syscall_summary: str | None = None
    syscall_path: str | None = None
    syscall_argv: list[str] | None = None
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
                agent_name=agent_name,
                syscall_impact=syscall_impact,
                syscall_payload=syscall_payload,
                prompt_text="",
                reasoning_text="",
            )
            return PipelineResult(
                status="skipped",
                syscall_name=syscall_impact.syscall_name,
                syscall_summary=self._syscall_summary(syscall_payload),
                syscall_path=self._syscall_path(syscall_payload),
                syscall_argv=self._syscall_argv(syscall_payload),
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
        prompt_text = self._clean_prompt_if_abrupt(agent_name, parser_result.prompt_text)
        reasoning_text = self.parser_manager.normalize_reasoning_text(
            response_payload,
            parser_result.reasoning_text,
        )
        event_id, event_path = self._write_event_json(
            agent_name=agent_name,
            syscall_impact=syscall_impact,
            syscall_payload=syscall_payload,
            prompt_text=prompt_text,
            reasoning_text=reasoning_text,
        )
        return PipelineResult(
            status="stored",
            syscall_name=syscall_impact.syscall_name,
            syscall_summary=self._syscall_summary(syscall_payload),
            syscall_path=self._syscall_path(syscall_payload),
            syscall_argv=self._syscall_argv(syscall_payload),
            affects_host_os=syscall_impact.affects_host_os,
            reason=syscall_impact.rationale,
            event_id=event_id,
            event_path=str(event_path),
            agent_name=agent_name,
            prompt_text=prompt_text,
            reasoning_text=reasoning_text,
            parser_path=str(parser_result.parser_path),
            schema_signature=parser_result.schema_signature,
            parser_source=parser_result.source,
        )

    def _write_event_json(
        self,
        *,
        agent_name: str,
        syscall_impact: SyscallImpact,
        syscall_payload: Any,
        prompt_text: str,
        reasoning_text: str,
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
            "agent_name": agent_name,
            "syscall": syscall_impact.syscall_name,
            "summary": self._syscall_summary(syscall_payload),
            "path": self._syscall_path(syscall_payload),
            "argv": self._syscall_argv(syscall_payload),
            "affects_host_os": syscall_impact.affects_host_os,
            "syscall_category": syscall_impact.category,
            "reason": syscall_impact.rationale,
            "syscall_mapping_source": syscall_impact.source,
            "is_known_syscall": syscall_impact.is_known,
            "prompt_text": prompt_text,
            "reasoning_text": reasoning_text,
            "created_at": timestamp,
        }
        event_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        return event_path.stem, event_path

    def _syscall_summary(self, syscall_payload: Any) -> str | None:
        if isinstance(syscall_payload, dict):
            value = syscall_payload.get("summary")
            if isinstance(value, str):
                return value
        return None

    def _syscall_path(self, syscall_payload: Any) -> str | None:
        if isinstance(syscall_payload, dict):
            value = syscall_payload.get("path")
            if isinstance(value, str):
                return value
        return None

    def _syscall_argv(self, syscall_payload: Any) -> list[str] | None:
        if isinstance(syscall_payload, dict):
            value = syscall_payload.get("argv")
            if isinstance(value, list):
                return [str(item) for item in value]
        return None

    def _clean_prompt_if_abrupt(self, agent_name: str, prompt_text: str) -> str:
        if self._has_prompt_contamination(prompt_text):
            return self.parser_manager.clean_prompt_text(prompt_text)
        previous_length = self._previous_prompt_length(agent_name)
        if previous_length is None or len(prompt_text) <= previous_length + 1000:
            return prompt_text
        return self.parser_manager.clean_prompt_text(prompt_text)

    def _has_prompt_contamination(self, prompt_text: str) -> bool:
        lowered = prompt_text.lower()
        markers = (
            "<system-reminder",
            "as you answer the user's questions",
            "<local-command-caveat",
            "<command-name>",
            "<command-message>",
            "<command-args>",
            "<local-command-stdout>",
            "<local-command-stderr>",
        )
        return any(marker in lowered for marker in markers)

    def _previous_prompt_length(self, agent_name: str) -> int | None:
        if not self.event_output_dir.is_dir():
            return None
        candidates = sorted(
            self.event_output_dir.glob("*.json"),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
        for candidate in candidates:
            try:
                payload = json.loads(candidate.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if payload.get("agent_name") != agent_name:
                continue
            prompt_text = payload.get("prompt_text")
            if isinstance(prompt_text, str):
                return len(prompt_text)
        return None

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
