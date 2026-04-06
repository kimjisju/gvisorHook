from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mitmproxy import http


TARGET_HOSTS = {"api.openai.com"}
LOG_PATH = Path(os.environ["GVISOR_HOOK_LLM_LOG_PATH"])
MAX_TEXT = int(os.environ.get("GVISOR_HOOK_LLM_MAX_TEXT", "32768"))


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def truncate_text(value: str) -> str:
    if len(value) <= MAX_TEXT:
        return value
    return value[:MAX_TEXT] + "\n...<truncated>..."


def parse_body(message: http.Message) -> Any:
    try:
        text = message.get_text(strict=False)
    except Exception as exc:  # pragma: no cover
        return f"<body unavailable: {exc!r}>"
    if not text:
        return None
    content_type = message.headers.get("content-type", "")
    if "application/json" in content_type:
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return truncate_text(text)
    return truncate_text(text)


def request_summary(body: Any) -> str:
    if not isinstance(body, dict):
        return "non-JSON request body"
    model = body.get("model", "unknown-model")
    messages = body.get("messages", [])
    tools = body.get("tools", [])
    last_roles = [msg.get("role", "?") for msg in messages[-3:] if isinstance(msg, dict)]
    last_user = ""
    for message in reversed(messages):
        if isinstance(message, dict) and message.get("role") == "user":
            content = message.get("content")
            if isinstance(content, str):
                last_user = truncate_text(content)
            elif isinstance(content, list):
                text_chunks = []
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text_chunks.append(str(item.get("text", "")))
                last_user = truncate_text(" ".join(text_chunks))
            break
    tool_names = []
    for tool in tools:
        if isinstance(tool, dict):
            function = tool.get("function")
            if isinstance(function, dict) and function.get("name"):
                tool_names.append(str(function["name"]))
    summary = f"model={model}; messages={len(messages)}; tools={len(tool_names)}"
    if last_roles:
        summary += f"; recent_roles={','.join(last_roles)}"
    if tool_names:
        summary += f"; tool_names={','.join(tool_names[:8])}"
    if last_user:
        summary += f"; last_user={last_user}"
    return summary


def response_summary(body: Any) -> str:
    if isinstance(body, dict):
        choices = body.get("choices", [])
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or choices[0].get("delta") or {}
            if isinstance(message, dict):
                tool_calls = message.get("tool_calls")
                if isinstance(tool_calls, list) and tool_calls:
                    names = []
                    for call in tool_calls:
                        if isinstance(call, dict):
                            function = call.get("function")
                            if isinstance(function, dict) and function.get("name"):
                                names.append(str(function["name"]))
                    if names:
                        return f"tool_calls={','.join(names[:8])}"
                content = message.get("content")
                if isinstance(content, str) and content:
                    return truncate_text(content)
        return "JSON response body"
    if isinstance(body, str) and "data:" in body:
        lines = [line.strip() for line in body.splitlines() if line.strip().startswith("data:")]
        preview = " | ".join(lines[:3])
        return truncate_text(f"stream_events={len(lines)}; preview={preview}")
    if isinstance(body, str) and body:
        return truncate_text(body)
    return "empty response"


def emit(record_type: str, payload: dict[str, Any]) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    with LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps({"type": record_type, "payload": payload}, ensure_ascii=False) + "\n")


def should_capture(flow: http.HTTPFlow) -> bool:
    return flow.request.pretty_host in TARGET_HOSTS


def request(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    body = parse_body(flow.request)
    started_at = utc_now()
    flow.metadata["gvisor_hook_started_at"] = started_at
    emit(
        "llm-upsert",
        {
            "id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "started_at": started_at,
            "status": "pending",
            "model": body.get("model") if isinstance(body, dict) else None,
            "request_summary": request_summary(body),
            "request_body": body,
            "response_status": None,
            "response_summary": None,
            "response_body": None,
            "error": None,
        },
    )


def response(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    request_body = parse_body(flow.request)
    response_body = parse_body(flow.response)
    emit(
        "llm-upsert",
        {
            "id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "started_at": flow.metadata.get("gvisor_hook_started_at", utc_now()),
            "status": "completed",
            "model": request_body.get("model") if isinstance(request_body, dict) else None,
            "request_summary": request_summary(request_body),
            "request_body": request_body,
            "response_status": flow.response.status_code,
            "response_summary": response_summary(response_body),
            "response_body": response_body,
            "error": None,
        },
    )


def error(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    request_body = parse_body(flow.request)
    emit(
        "llm-upsert",
        {
            "id": flow.id,
            "method": flow.request.method,
            "url": flow.request.pretty_url,
            "started_at": flow.metadata.get("gvisor_hook_started_at", utc_now()),
            "status": "error",
            "model": request_body.get("model") if isinstance(request_body, dict) else None,
            "request_summary": request_summary(request_body),
            "request_body": request_body,
            "response_status": None,
            "response_summary": None,
            "response_body": None,
            "error": str(flow.error) if flow.error is not None else "unknown mitmproxy error",
        },
    )
