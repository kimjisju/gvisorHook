from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


Decision = Literal["allow", "deny"]
EventStatus = Literal["pending", "allowed", "denied", "timeout", "error"]
LLMStatus = Literal["pending", "completed", "error"]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(slots=True)
class SyscallEvent:
    id: str
    container_id: str
    pid: int
    tid: int
    syscall: str
    summary: str
    path: str | None = None
    argv: list[str] | None = None
    started_at: str = field(default_factory=utc_now)
    status: EventStatus = "pending"
    errno: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class LLMExchange:
    id: str
    method: str
    url: str
    started_at: str = field(default_factory=utc_now)
    status: LLMStatus = "pending"
    session_id: str | None = None
    model: str | None = None
    request_summary: str | None = None
    request_body: Any | None = None
    request_body_bytes: int | None = None
    request_body_sha256: str | None = None
    request_headers_sha256: str | None = None
    request_content_type: str | None = None
    request_headers_path: str | None = None
    request_body_path: str | None = None
    response_status: int | None = None
    response_summary: str | None = None
    response_body: Any | None = None
    response_body_bytes: int | None = None
    response_body_sha256: str | None = None
    response_headers_sha256: str | None = None
    response_content_type: str | None = None
    response_headers_path: str | None = None
    response_body_path: str | None = None
    meta_path: str | None = None
    artifact_dir: str | None = None
    is_stream: bool | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BrokerEnvelope:
    type: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "payload": self.payload}
