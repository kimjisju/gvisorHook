from __future__ import annotations

import argparse
import json
from collections import Counter
from json import JSONDecodeError
from pathlib import Path
from typing import Any

from structured_pipeline import SyscallNormalizationPipeline


def _load_payload(path: Path, *, kind: str) -> Any:
    text = path.read_text(encoding="utf-8-sig").strip()
    if not text:
        raise ValueError(f"{kind} file is empty: {path}")

    try:
        return json.loads(text)
    except JSONDecodeError:
        if kind == "response":
            parsed_sse = _parse_sse_response(text)
            if parsed_sse is not None:
                return parsed_sse
        if kind == "syscall":
            return _parse_plaintext_syscall(text)
        return {"format": "raw_text", "text": text, "raw_text": text}


def _parse_plaintext_syscall(text: str) -> dict[str, Any]:
    parts = text.split(maxsplit=1)
    name = parts[0]
    arguments_text = parts[1] if len(parts) > 1 else ""
    return {
        "name": name,
        "arguments_text": arguments_text,
        "raw_text": text,
        "format": "plaintext",
    }


def _parse_sse_response(text: str) -> dict[str, Any] | None:
    if not text.startswith("event: ") and "\nevent: " not in text:
        return None

    events: list[dict[str, Any]] = []
    current_event: str | None = None
    current_data_lines: list[str] = []

    def flush() -> None:
        nonlocal current_event, current_data_lines
        if current_event is None:
            current_data_lines = []
            return
        data_text = "\n".join(current_data_lines).strip()
        event_record: dict[str, Any] = {"event": current_event}
        if data_text:
            try:
                event_record["data"] = json.loads(data_text)
            except JSONDecodeError:
                event_record["data_raw"] = data_text
        events.append(event_record)
        current_event = None
        current_data_lines = []

    for raw_line in text.splitlines():
        line = raw_line.rstrip("\n")
        if not line.strip():
            flush()
            continue
        if line.startswith("event: "):
            if current_event is not None and current_data_lines:
                flush()
            current_event = line[7:].strip()
            continue
        if line.startswith("data: "):
            current_data_lines.append(line[6:])
            continue
        current_data_lines.append(line)
    flush()

    event_types = Counter(event["event"] for event in events)
    created_response = None
    completed_response = None
    output_items: list[dict[str, Any]] = []
    function_calls: list[dict[str, Any]] = []
    function_argument_events: list[dict[str, Any]] = []
    reasoning_summaries: list[str] = []
    assistant_text_parts: list[str] = []
    text_candidates: list[str] = []

    for event in events:
        data = event.get("data")
        if not isinstance(data, dict):
            continue

        if event["event"] == "response.created":
            created_response = data.get("response")
        elif event["event"] == "response.completed":
            completed_response = data.get("response")

        item = data.get("item")
        if isinstance(item, dict):
            output_items.append(item)

            item_type = item.get("type")
            if item_type == "reasoning":
                summary = item.get("summary")
                if isinstance(summary, list):
                    reasoning_summaries.extend(str(part).strip() for part in summary if str(part).strip())
                elif isinstance(summary, str) and summary.strip():
                    reasoning_summaries.append(summary.strip())

            if item_type == "function_call":
                normalized_call = dict(item)
                arguments = normalized_call.get("arguments")
                if isinstance(arguments, str) and arguments.strip():
                    text_candidates.append(arguments.strip())
                    try:
                        normalized_call["parsed_arguments"] = json.loads(arguments)
                    except JSONDecodeError:
                        pass
                    parsed_arguments = normalized_call.get("parsed_arguments")
                    if isinstance(parsed_arguments, dict):
                        justification = parsed_arguments.get("justification")
                        if isinstance(justification, str) and justification.strip():
                            text_candidates.append(justification.strip())
                function_calls.append(normalized_call)

            content = item.get("content")
            if isinstance(content, list):
                for content_item in content:
                    if not isinstance(content_item, dict):
                        continue
                    text_value = content_item.get("text")
                    if isinstance(text_value, str) and text_value.strip():
                        assistant_text_parts.append(text_value.strip())
                        text_candidates.append(text_value.strip())

        if event["event"] == "response.function_call_arguments.done":
            arguments = data.get("arguments")
            normalized_done = dict(data)
            if isinstance(arguments, str) and arguments.strip():
                text_candidates.append(arguments.strip())
                try:
                    normalized_done["parsed_arguments"] = json.loads(arguments)
                except JSONDecodeError:
                    pass
                parsed_arguments = normalized_done.get("parsed_arguments")
                if isinstance(parsed_arguments, dict):
                    justification = parsed_arguments.get("justification")
                    if isinstance(justification, str) and justification.strip():
                        text_candidates.append(justification.strip())
            function_argument_events.append(normalized_done)

        delta = data.get("delta")
        if isinstance(delta, str) and delta.strip():
            if event["event"].startswith("response.output_text"):
                assistant_text_parts.append(delta)
                text_candidates.append(delta)

    assistant_text = "".join(assistant_text_parts).strip()
    if assistant_text:
        text_candidates.append(assistant_text)

    return {
        "format": "sse",
        "raw_text": text,
        "events": events,
        "event_types": dict(event_types),
        "response": completed_response or created_response,
        "created_response": created_response,
        "completed_response": completed_response,
        "output_items": output_items,
        "function_calls": function_calls,
        "function_call_arguments": function_argument_events,
        "assistant_text": assistant_text,
        "reasoning_summaries": reasoning_summaries,
        "text_candidates": text_candidates,
    }


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Normalize proxy-hooked LLM data and gVisor syscalls into per-event JSON files."
    )
    parser.add_argument("--event-file", type=Path, help="JSON file with agent_name, request, response, syscall")
    parser.add_argument("--agent-name", type=str, help="Agent name when using separate request/response/syscall files")
    parser.add_argument("--request-file", type=Path, help="JSON file for the proxy request payload")
    parser.add_argument("--response-file", type=Path, help="JSON file for the proxy response payload")
    parser.add_argument("--syscall-file", type=Path, help="JSON file for the syscall payload")
    parser.add_argument("--db-path", type=Path, default=None, help="Override SQLite database path")
    parser.add_argument("--event-output-dir", type=Path, default=None, help="Directory for per-event JSON results")
    parser.add_argument("--mapping-csv", type=Path, default=None, help="Override syscall mapping CSV path")
    parser.add_argument("--parser-dir", type=Path, default=None, help="Override generated parser directory")
    args = parser.parse_args()

    if args.event_file:
        event = _load_payload(args.event_file, kind="event")
        agent_name = event["agent_name"]
        request_payload = event["request"]
        response_payload = event["response"]
        syscall_payload = event["syscall"]
    else:
        missing = [
            name
            for name, value in {
                "agent_name": args.agent_name,
                "request_file": args.request_file,
                "response_file": args.response_file,
                "syscall_file": args.syscall_file,
            }.items()
            if value is None
        ]
        if missing:
            joined = ", ".join(missing)
            raise SystemExit(f"Missing required arguments when --event-file is not used: {joined}")
        agent_name = args.agent_name
        request_payload = _load_payload(args.request_file, kind="request")
        response_payload = _load_payload(args.response_file, kind="response")
        syscall_payload = _load_payload(args.syscall_file, kind="syscall")

    pipeline = SyscallNormalizationPipeline(
        base_dir=Path(__file__).resolve().parent,
        db_path=args.db_path,
        mapping_csv_path=args.mapping_csv,
        parser_dir=args.parser_dir,
        event_output_dir=args.event_output_dir,
    )
    result = pipeline.process_event(
        agent_name=agent_name,
        request_payload=request_payload,
        response_payload=response_payload,
        syscall_payload=syscall_payload,
    )
    print(
        json.dumps(
            {
                "status": result.status,
                "event_id": result.event_id,
                "event_path": result.event_path,
                "agent_name": result.agent_name,
                "syscall_name": result.syscall_name,
                "summary": result.syscall_summary,
                "path": result.syscall_path,
                "argv": result.syscall_argv,
                "affects_host_os": result.affects_host_os,
                "reason": result.reason,
                "schema_signature": result.schema_signature,
                "parser_source": result.parser_source,
                "parser_path": result.parser_path,
                "prompt_text": result.prompt_text,
                "reasoning_text": result.reasoning_text,
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
