from __future__ import annotations

import base64
import gzip
import json
import os
import sys
from datetime import datetime, timezone
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
CAPTURE_BODY_MARKERS = ("tools", "role", "systeminstruction")
FLOW_SEQUENCE_BY_ID: dict[str, int] = {}
NEXT_FLOW_SEQUENCE = 1


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


def body_content_encoding(message: http.Message | None) -> str:
    if message is None:
        return ""
    return message.headers.get("content-encoding", "")


def decoded_body(message: http.Message | None) -> bytes:
    body = raw_body(message)
    if "gzip" not in body_content_encoding(message).lower():
        return body
    try:
        return gzip.decompress(body)
    except (OSError, EOFError):
        return body


def handshake_http_flow(flow: Any) -> http.HTTPFlow:
    return getattr(flow, "handshake_flow", flow)


def flow_started_at(flow: Any, message: Any | None = None) -> str:
    timestamp = getattr(message, "timestamp", None)
    if isinstance(timestamp, (int, float)):
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat()
    if isinstance(timestamp, str):
        return timestamp
    http_flow = handshake_http_flow(flow)
    return getattr(http_flow, "metadata", {}).get("gvisor_hook_started_at", utc_now())


def websocket_messages(flow: Any) -> list[Any]:
    websocket = getattr(flow, "websocket", None)
    messages = getattr(websocket, "messages", None) or getattr(flow, "messages", None)
    return list(messages or [])


def parse_request_json(body: bytes, content_type: str = "") -> Any | None:
    if not body:
        return None
    try:
        return json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def parse_sse_json_array(body: bytes) -> list[Any] | None:
    if not body:
        return None
    try:
        text = body.decode("utf-8")
    except UnicodeDecodeError:
        return None
    events: list[Any] = []
    for block in text.replace("\r\n", "\n").replace("\r", "\n").split("\n\n"):
        data_lines: list[str] = []
        for line in block.split("\n"):
            if not line.startswith("data:"):
                continue
            data_lines.append(line[5:].lstrip())
        if not data_lines:
            continue
        data = "\n".join(data_lines).strip()
        if not data or data == "[DONE]":
            continue
        try:
            events.append(json.loads(data))
        except json.JSONDecodeError:
            return None
    return events or None


def marker_text(value: bytes | str) -> str:
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="ignore")
    return "".join(ch.lower() for ch in value if ch.isalnum())


def json_has_capture_marker(value: Any) -> bool:
    markers = {marker_text(marker) for marker in CAPTURE_BODY_MARKERS}
    if isinstance(value, dict):
        for key, child in value.items():
            if marker_text(str(key)) in markers:
                return True
            if json_has_capture_marker(child):
                return True
    elif isinstance(value, list):
        return any(json_has_capture_marker(item) for item in value)
    return False


def should_persist_body(body: bytes | str) -> bool:
    if isinstance(body, str):
        body = body.encode("utf-8")
    parsed = parse_request_json(body)
    return json_has_capture_marker(parsed)


def body_json_value(body: bytes) -> Any:
    parsed = parse_request_json(body)
    if parsed is not None:
        return parsed
    parsed_sse = parse_sse_json_array(body)
    if parsed_sse is not None:
        return parsed_sse
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return {
            "encoding": "base64",
            "body": base64.b64encode(body).decode("ascii"),
        }


def body_json_text(body: bytes) -> str:
    return json.dumps(body_json_value(body), ensure_ascii=False, indent=2)


def write_body_json(path: Path, body: bytes) -> None:
    path.write_text(body_json_text(body) + "\n", encoding="utf-8")


def should_capture(flow: Any) -> bool:
    http_flow = handshake_http_flow(flow)
    if TARGET_HOSTS and http_flow.request.pretty_host not in TARGET_HOSTS:
        return False
    return True


def should_persist_response(status_code: int) -> bool:
    return 200 <= status_code < 300 and status_code != 204


def sequenced_flow_id(flow_id: str) -> str:
    global NEXT_FLOW_SEQUENCE
    if flow_id not in FLOW_SEQUENCE_BY_ID:
        FLOW_SEQUENCE_BY_ID[flow_id] = NEXT_FLOW_SEQUENCE
        NEXT_FLOW_SEQUENCE += 1
    return f"{FLOW_SEQUENCE_BY_ID[flow_id]:06d}_{flow_id}"


def request_metadata(flow: http.HTTPFlow) -> dict[str, Any]:
    body = decoded_body(flow.request)
    request_headers = request_headers_bytes(flow.request)
    content_type = flow.request.headers.get("content-type", "")
    parsed_json = parse_request_json(body)
    parsed_dict = parsed_json if isinstance(parsed_json, dict) else None
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
        "model": parsed_dict.get("model") if parsed_dict else None,
        "is_stream": bool(parsed_dict.get("stream")) if parsed_dict else False,
        "json_payload": parsed_json,
    }


def response_metadata(flow: http.HTTPFlow) -> dict[str, Any]:
    response = flow.response
    body = decoded_body(response)
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


def websocket_message_body(message: Any) -> bytes:
    content = getattr(message, "content", b"")
    if content is None:
        return b""
    if isinstance(content, bytes):
        return content
    if isinstance(content, str):
        return content.encode("utf-8")
    return bytes(content)


def websocket_body_text(body: bytes) -> str:
    if not body:
        return ""
    return body.decode("utf-8", errors="replace")


def write_flow_files(flow_id: str, *, request: dict[str, Any], response: dict[str, Any] | None) -> dict[str, Path]:
    paths = flow_artifact_paths(SESSION, flow_id)
    paths["request_headers_path"].write_bytes(request["headers"])
    write_body_json(paths["request_body_path"], request["body"])
    if response is not None:
        paths["response_headers_path"].write_bytes(response["headers"])
        write_body_json(paths["response_body_path"], response["body"])
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
    if "websocket_transcript_path" in paths:
        meta["websocket"] = {
            "transcript_path": str(paths["websocket_transcript_path"]),
            "transcript_ndjson_path": str(paths["websocket_transcript_ndjson_path"]),
            "frame_count": payload.get("websocket_frame_count"),
            "client_frame_count": payload.get("websocket_client_frame_count"),
            "server_frame_count": payload.get("websocket_server_frame_count"),
        }
    write_json(paths["meta_path"], meta)


def build_payload(
    flow: http.HTTPFlow,
    *,
    flow_id: str,
    status: str,
    request: dict[str, Any],
    response: dict[str, Any] | None,
    error: str | None,
) -> dict[str, Any]:
    started_at = flow.metadata.get("gvisor_hook_started_at", utc_now())
    paths = flow_artifact_paths(SESSION, flow_id)
    payload = {
        "id": flow_id,
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
    flow_id = sequenced_flow_id(flow.id)
    paths = write_flow_files(flow_id, request=request, response=response)
    payload = build_payload(flow, flow_id=flow_id, status=status, request=request, response=response, error=error)
    write_meta(paths, payload)
    emit(payload)
    write_indexes(payload)


def websocket_frame_record(flow: Any, message: Any, *, index: int) -> dict[str, Any]:
    body = websocket_message_body(message)
    direction = "client" if getattr(message, "from_client", False) else "server"
    return {
        "index": index,
        "direction": direction,
        "timestamp": flow_started_at(flow, message),
        "body": body,
        "body_text": websocket_body_text(body),
        "body_bytes": len(body),
        "body_sha256": sha256_hex(body),
    }


def websocket_frame_text(record: dict[str, Any]) -> str:
    return (
        f"[{record['index']:06d} {record['timestamp']} {record['direction']} "
        f"bytes={record['body_bytes']} sha256={record['body_sha256']}]\n"
        f"{record['body_text']}\n"
    )


def websocket_transcript_bytes(records: list[dict[str, Any]], *, direction: str | None = None) -> bytes:
    selected = [record for record in records if direction is None or record["direction"] == direction]
    if not selected:
        return b""
    return "\n".join(websocket_frame_text(record).rstrip() for record in selected).encode("utf-8")


def websocket_records_json(records: list[dict[str, Any]], *, direction: str | None = None) -> list[dict[str, Any]]:
    selected = [record for record in records if direction is None or record["direction"] == direction]
    return [
        {
            "index": record["index"],
            "direction": record["direction"],
            "timestamp": record["timestamp"],
            "body": body_json_value(record["body"]),
            "body_bytes": record["body_bytes"],
            "body_sha256": record["body_sha256"],
        }
        for record in selected
    ]


def websocket_turns(records: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    turns: list[list[dict[str, Any]]] = []
    for record in records:
        if record["direction"] == "client" or not turns:
            turns.append([record])
        else:
            turns[-1].append(record)
    return turns


def websocket_turn_has_capture_marker(records: list[dict[str, Any]]) -> bool:
    return any(
        record["direction"] == "client" and should_persist_body(record["body"])
        for record in records
    )


def websocket_model(records: list[dict[str, Any]]) -> str | None:
    for record in records:
        if record["direction"] != "client":
            continue
        parsed = parse_request_json(record["body"])
        if isinstance(parsed, dict) and parsed.get("model"):
            return parsed["model"]
    return None


def persist_websocket_flow(flow: Any) -> None:
    http_flow = handshake_http_flow(flow)
    messages = websocket_messages(flow)
    if not messages:
        return
    records = [
        websocket_frame_record(flow, message, index=index)
        for index, message in enumerate(messages, start=1)
    ]
    turns = websocket_turns(records)
    turn_index = len(turns)
    turn_records = turns[-1]
    if not websocket_turn_has_capture_marker(turn_records):
        return
    flow_id = sequenced_flow_id(f"{flow.id}-websocket-turn-{turn_index:06d}")
    paths = flow_artifact_paths(SESSION, flow_id)
    paths["websocket_transcript_path"] = paths["flow_dir"] / "websocket_transcript.txt"
    paths["websocket_transcript_ndjson_path"] = paths["flow_dir"] / "websocket_transcript.ndjson"
    request_headers = request_headers_bytes(http_flow.request)
    response_headers = response_headers_bytes(http_flow.response) if http_flow.response is not None else b""
    request_body = websocket_transcript_bytes(turn_records, direction="client")
    response_body = websocket_transcript_bytes(turn_records, direction="server")
    transcript_body = websocket_transcript_bytes(turn_records)
    paths["request_headers_path"].write_bytes(request_headers)
    write_json(paths["request_body_path"], websocket_records_json(turn_records, direction="client"))
    paths["response_headers_path"].write_bytes(response_headers)
    write_json(paths["response_body_path"], websocket_records_json(turn_records, direction="server"))
    paths["websocket_transcript_path"].write_bytes(transcript_body)
    paths["websocket_transcript_ndjson_path"].write_text(
        "\n".join(
            json.dumps(
                {
                    "index": record["index"],
                    "direction": record["direction"],
                    "timestamp": record["timestamp"],
                    "body": record["body_text"],
                    "body_bytes": record["body_bytes"],
                    "body_sha256": record["body_sha256"],
                },
                ensure_ascii=False,
            )
            for record in turn_records
        )
        + "\n",
        encoding="utf-8",
    )

    request_body_text = websocket_body_text(request_body)
    response_body_text = websocket_body_text(response_body)
    client_frame_count = sum(1 for record in turn_records if record["direction"] == "client")
    server_frame_count = len(turn_records) - client_frame_count
    payload = {
        "id": flow_id,
        "session_id": SESSION_ID,
        "method": "WEBSOCKET_TURN",
        "url": http_flow.request.pretty_url,
        "started_at": turn_records[0]["timestamp"],
        "status": "completed",
        "model": websocket_model(turn_records),
        "request_summary": (
            f"websocket_turn={turn_index}; "
            f"client_frames={client_frame_count}; "
            f"client_bytes={len(request_body)}"
        ),
        "request_body": request_body_text,
        "request_body_bytes": len(request_body),
        "request_body_sha256": sha256_hex(request_body),
        "request_headers_sha256": sha256_hex(request_headers),
        "request_content_type": http_flow.request.headers.get("content-type", ""),
        "request_headers_path": str(paths["request_headers_path"]),
        "request_body_path": str(paths["request_body_path"]),
        "response_status": http_flow.response.status_code if http_flow.response is not None else None,
        "response_summary": (
            f"websocket_turn={turn_index}; "
            f"server_frames={server_frame_count}; "
            f"server_bytes={len(response_body)}; "
            f"transcript_path={paths['websocket_transcript_path']}"
        ),
        "response_body": response_body_text,
        "response_body_bytes": len(response_body),
        "response_body_sha256": sha256_hex(response_body),
        "response_headers_sha256": sha256_hex(response_headers),
        "response_content_type": http_flow.response.headers.get("content-type", "")
        if http_flow.response is not None
        else "",
        "response_headers_path": str(paths["response_headers_path"]),
        "response_body_path": str(paths["response_body_path"]),
        "meta_path": str(paths["meta_path"]),
        "artifact_dir": str(paths["flow_dir"]),
        "is_stream": True,
        "error": None,
        "websocket_frame_count": len(turn_records),
        "websocket_client_frame_count": client_frame_count,
        "websocket_server_frame_count": server_frame_count,
    }
    write_meta(paths, payload)
    payload.pop("websocket_frame_count")
    payload.pop("websocket_client_frame_count")
    payload.pop("websocket_server_frame_count")
    emit(payload)
    write_indexes(payload)


def request(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    flow.metadata["gvisor_hook_started_at"] = utc_now()
    if should_persist_body(decoded_body(flow.request)):
        sequenced_flow_id(flow.id)


def response(flow: http.HTTPFlow) -> None:
    if not should_capture(flow):
        return
    if not should_persist_body(decoded_body(flow.request)):
        return
    response = response_metadata(flow)
    if not should_persist_response(response["status_code"]):
        return
    persist_flow(flow, status="completed", response=response)


def websocket_message(flow: Any) -> None:
    if not should_capture(flow):
        return
    persist_websocket_flow(flow)


def error(flow: http.HTTPFlow) -> None:
    return
