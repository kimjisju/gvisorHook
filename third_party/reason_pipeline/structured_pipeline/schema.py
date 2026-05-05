from __future__ import annotations

import hashlib
import json
import re
from typing import Any


def _canonical_shape(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _canonical_shape(value[key]) for key in sorted(value)}
    if isinstance(value, list):
        return [_canonical_shape(item) for item in value[:3]]
    return type(value).__name__


def build_schema_signature(request_payload: Any, response_payload: Any) -> str:
    shape = {
        "request": _canonical_shape(request_payload),
        "response": _canonical_shape(response_payload),
    }
    serialized = json.dumps(shape, ensure_ascii=True, sort_keys=True)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def slugify(value: str) -> str:
    lowered = value.strip().lower()
    normalized = re.sub(r"[^a-z0-9]+", "_", lowered)
    return normalized.strip("_") or "unknown_agent"


def extract_syscall_name(syscall_payload: Any) -> str:
    if isinstance(syscall_payload, str):
        return syscall_payload

    if not isinstance(syscall_payload, dict):
        raise ValueError("syscall payload must be a string or dict")

    preferred_keys = ("name", "syscall_name", "syscall", "event_name")
    for key in preferred_keys:
        value = syscall_payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()

    nested_keys = ("event", "syscall", "metadata", "record")
    for key in nested_keys:
        nested = syscall_payload.get(key)
        if nested is None:
            continue
        try:
            return extract_syscall_name(nested)
        except ValueError:
            continue

    raise ValueError("could not determine syscall name from payload")
