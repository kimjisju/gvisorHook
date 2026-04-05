from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Literal


Decision = Literal["allow", "deny"]
EventStatus = Literal["pending", "allowed", "denied", "timeout", "error"]


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
class BrokerEnvelope:
    type: str
    payload: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "payload": self.payload}
