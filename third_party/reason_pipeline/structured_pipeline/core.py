from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .db import PipelineDatabase, SyscallImpact
from .parser_manager import ParserManager
from .schema import extract_syscall_name


@dataclass
class PipelineResult:
    status: str
    syscall_name: str
    affects_host_os: int
    reason: str
    event_id: int | None = None
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
    ) -> None:
        resolved_base_dir = base_dir or Path(__file__).resolve().parent.parent
        resolved_db_path = db_path or resolved_base_dir / "data" / "pipeline.db"
        resolved_mapping_path = mapping_csv_path or resolved_base_dir / "data" / "syscall_host_impact_map.csv"
        resolved_parser_dir = parser_dir or resolved_base_dir / "generated_parsers"

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
            return PipelineResult(
                status="skipped",
                syscall_name=syscall_impact.syscall_name,
                affects_host_os=0,
                reason=self._format_skip_reason(syscall_impact),
                agent_name=agent_name,
            )

        parser_result = self.parser_manager.resolve(
            agent_name=agent_name,
            request_payload=request_payload,
            response_payload=response_payload,
        )
        event_id = self.database.save_normalized_event(
            agent_name=agent_name,
            schema_signature=parser_result.schema_signature,
            syscall_name=syscall_impact.syscall_name,
            affects_host_os=syscall_impact.affects_host_os,
            prompt_text=parser_result.prompt_text,
            reasoning_text=parser_result.reasoning_text,
            request_payload=request_payload,
            response_payload=response_payload,
            syscall_payload=syscall_payload,
            parser_path=str(parser_result.parser_path),
        )
        return PipelineResult(
            status="stored",
            syscall_name=syscall_impact.syscall_name,
            affects_host_os=syscall_impact.affects_host_os,
            reason=syscall_impact.rationale,
            event_id=event_id,
            agent_name=agent_name,
            prompt_text=parser_result.prompt_text,
            reasoning_text=parser_result.reasoning_text,
            parser_path=str(parser_result.parser_path),
            schema_signature=parser_result.schema_signature,
            parser_source=parser_result.source,
        )

    def _format_skip_reason(self, syscall_impact: SyscallImpact) -> str:
        return (
            f"syscall '{syscall_impact.syscall_name}' is marked as non-host-impacting "
            f"({syscall_impact.category}): {syscall_impact.rationale}"
        )
