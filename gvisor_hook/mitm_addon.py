from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from mitmproxy import http

REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from gvisor_hook.dataset import (
    append_ndjson,
    bytes_preview,
    dataset_session_from_root,
    flow_artifact_paths,
    header_block,
    sha256_hex,
    utc_now,
    write_json,
)


LOG_PATH = Path(os.environ["GVISOR_HOOK_LLM_LOG_PATH"])
SESSION_ROOT = Path(os.environ["GVISOR_HOOK_DATASET_SESSION_DIR"])
DATASET_ROOT = Path(os.environ["GVISOR_HOOK_DATASET_ROOT"])
SESSION_ID = os.environ["GVISOR_HOOK_SESSION_ID"]
TARGET_HOSTS = {
    host.strip()
    for host in os.environ.get("GVISOR_HOOK_LLM_TARGET_HOSTS", "").split(",")
    if host.strip()
}
SESSION = dataset_session_from_root(SESSION_ROOT)


def normalize_http_version(value: str | None) -> str:
    if not value:
        return "HTTP/1.1"
    if value.startswith("HTTP/"):
        return value
    return f"HTTP/{value}"


def request_start_line(message: http.Request) -> str:
    target = message.path or message.pretty_url
    return f"{message.method} {target} {normalize_http_version(message.http_version)}"


def response_start_line(message: http.Response) -> str:
    reason = message.reason or ""
    return f"{normalize_http_version(message.http_version)} {message.status_code} {reason}".rstrip()


def request_headers_bytes(message: http.Request) -> bytes:
    return header_block(request_start_line(message), message.headers.fields)


def response_headers_bytes(message: http.Response) -> bytes:
    return header_block(response_start_line(message), message.headers.fields)


def raw_body(message: http.Message | None) -> bytes:
    if message is None or message.raw_content is None:
        return b""
    return message.raw_content


def should_capture(flow: http.HTTPFlow) -> bool:
    if not TARGET_HOSTS:
        return True
    return flow.request.pretty_host in TARGET_HOSTS


def parse_request_json(body: bytes, content_type: str) -> dict[str, Any] | None:
    if not body or "application/json" not in content_type.lower():
        return None
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if isinstance(payload, dict):
        return payload
    return None


def request_metadata(flow: http.HTTPFlow) -> dict[str, Any]:
    body = raw_body(flow.request)
    request_headers = request_headers_bytes(flow.request)
    content_type = flow.request.headers.get("content-type", "")
    parsed_json = parse_request_json(body, content_type)
    return {
        "method": flow.request.method,
        "url": flow.request.pretty_url,
        "http_version": normalize_http_version(flow.request.http_version),
        "content_type": content_type,
        "headers": request_headers,
        "body": body,
        "body_preview": bytes_preview(body),
        "headers_sha256": sha256_hex(request_headers),
        "body_sha256": sha256_hex(body),
        "body_bytes": len(body),
        "model": parsed_json.get("model") if parsed_json else None,
        "is_stream": bool(parsed_json.get("stream")) if parsed_json else False,
        "json_payload": parsed_json,
    }


def response_metadata(flow: http.HTTPFlow) -> dict[str, Any]:
    response = flow.response
    body = raw_body(response)
    headers = response_headers_bytes(response)
    content_type = response.headers.get("content-type", "")
    return {
        "status_code": response.status_code,
        "reason": response.reason,
        "http_version": normalize_http_version(response.http_version),
        "content_type": content_type,
        "headers": headers,
        "body": body,
        "body_preview": bytes_preview(body),
        "headers_sha256": sha256_hex(headers),
        "body_sha256": sha256_hex(body),
        "body_bytes": len(body),
        "is_stream": "text/event-stream" in content_type.lower(),
    }


def write_flow_files(flow_id: str, *, request: dict[str, Any], response: dict[str, Any] | None) -> dict[str, Path]:
    paths = flow_artifact_paths(SESSION, flow_id)
    paths["request_headers_path"].write_bytes(request["headers"])
    paths["request_body_path"].write_bytes(request["body"])
    if response is not None:
        paths["response_headers_path"].write_bytes(response["headers"])
        paths["response_body_path"].write_bytes(response["body"])
    return paths


def emit(payload: dict[str, Any]) -> None:
    append_ndjson(LOG_PATH, {"type": "llm-upsert", "payload": payload})


def write_indexes(payload: dict[str, Any]) -> None:
    envelope = {"type": "llm-upsert", "payload": payload}
    append_ndjson(SESSION.session_index_path, envelope)
    append_ndjson(DATASET_ROOT / "index.ndjson", envelope)


def write_meta(paths: dict[str, Path], payload: dict[str, Any]) -> None:
    meta = {
        "session_id": SESSION_ID,
        "flow_id": payload["id"],
        "method": payload["method"],
        "url": payload["url"],
        "started_at": payload["started_at"],
        "status": payload["status"],
        "model": payload.get("model"),
        "response_status": payload.get("response_status"),
        "error": payload.get("error"),
        "request": {
            "headers_path": str(paths["request_headers_path"]),
            "body_path": str(paths["request_body_path"]),
            "headers_sha256": payload.get("request_headers_sha256"),
            "body_sha256": payload.get("request_body_sha256"),
            "body_bytes": payload.get("request_body_bytes"),
            "content_type": payload.get("request_content_type"),
            "is_stream": payload.get("is_stream"),
        },
        "response": {
            "headers_path": str(paths["response_headers_path"]),
            "body_path": str(paths["response_body_path"]),
            "headers_sha256": payload.get("response_headers_sha256"),
            "body_sha256": payload.get("response_body_sha256"),
            "body_bytes": payload.get("response_body_bytes"),
            "content_type": payload.get("response_content_type"),
        },
    }
    write_json(paths["meta_path"], meta)


def build_payload(
    flow: http.HTTPFlow,
    *,
    status: str,
    request: dict[str, Any],
    response: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    started_at = flow.metadata.get("gvisor_hook_started_at", utc_now())
    paths = flow_artifact_paths(SESSION, flow.id)
    payload = {
        "id": flow.id,
        "session_id": SESSION_ID,
        "method": request["method"],
        "url": request["url"],
        "started_at": started_at,
        "status": status,
        "model": request["model"],
        "request_summary": (
            f"request_bytes={request['body_bytes']}; content_type={request['content_type'] or 'unknown'}"
        ),
        "request_body": request["body_preview"],
        "request_body_bytes": request["body_bytes"],
        "request_body_sha256": request["body_sha256"],
        "request_headers_sha256": request["headers_sha256"],
        "request_content_type": request["content_type"],
        "request_headers_path": str(paths["request_headers_path"]),
        "request_body_path": str(paths["request_body_path"]),
        "response_status": None if response is None else response["status_code"],
        "response_summary": None
        if response is None
        else f"response_bytes={response['body_bytes']}; content_type={response['content_type'] or 'unknown'}",
        "response_body": None if response is None else response["body_preview"],
        "response_body_bytes": None if response is None else response["body_bytes"],
        "response_body_sha256": None if response is None else response["body_sha256"],
        "response_headers_sha256": None if response is None else response["headers_sha256"],
        "response_content_type": None if response is None else response["content_type"],
        "response_headers_path": str(paths["response_headers_path"]),
        "response_body_path": str(paths["response_body_path"]),
        "meta_path": str(paths["meta_path"]),
        "artifact_dir": str(paths["flow_dir"]),
        "is_stream": request["is_stream"] or (False if response is None else response["is_stream"]),
        "error": error,
    }
    return payload


def persist_flow(
    flow: http.HTTPFlow,
    *,
    status: str,
    response: dict[str, Any] | None = None,
    error: str | None = None,
) -> None:
    request = request_metadata(flow)
    paths = write_flow_files(flow.id, request=request, response=response)
    payload = build_payload(flow, status=status, request=request, response=response, error=error)
    write_meta(paths, payload)
    emit(payload)
    write_indexes(payload)


def request(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    started_at = utc_now()
    flow.metadata["gvisor_hook_started_at"] = started_at
    persist_flow(flow, status="pending")


def response(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    persist_flow(flow, status="completed", response=response_metadata(flow))


def error(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    persist_flow(
        flow,
        status="error",
        error=str(flow.error) if flow.error is not None else "unknown mitmproxy error",
    )
