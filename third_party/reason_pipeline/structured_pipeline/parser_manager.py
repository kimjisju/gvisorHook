from __future__ import annotations

import importlib.util
import json
import re
from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent
from typing import Any

from .db import PipelineDatabase
from .schema import build_schema_signature, slugify

PARSER_POLICY_MARKER = "DIALOG_PROMPT_CONTEXT_V2"
MODEL_REPO_ID = "unsloth/Qwen3.5-2B-GGUF"


class ParserGenerationError(RuntimeError):
    pass


@dataclass
class ParserResult:
    schema_signature: str
    parser_path: Path
    parser_code: str
    prompt_text: str
    reasoning_text: str
    source: str


class ParserManager:
    def __init__(self, database: PipelineDatabase, parser_dir: Path) -> None:
        self.database = database
        self.parser_dir = parser_dir
        self.parser_dir.mkdir(parents=True, exist_ok=True)

    def resolve(
        self,
        *,
        agent_name: str,
        request_payload: Any,
        response_payload: Any,
    ) -> ParserResult:
        schema_signature = build_schema_signature(request_payload, response_payload)
        cached = self.database.get_parser_record(agent_name, schema_signature)

        if cached:
            try:
                if PARSER_POLICY_MARKER not in str(cached.get("parser_code", "")):
                    raise ParserGenerationError("cached parser uses an older prompt extraction policy")
                cached_path = Path(cached["parser_path"])
                prompt_text, reasoning_text = self._validate_parser(
                    parser_path=cached_path,
                    request_payload=request_payload,
                    response_payload=response_payload,
                )
                return ParserResult(
                    schema_signature=schema_signature,
                    parser_path=cached_path,
                    parser_code=cached["parser_code"],
                    prompt_text=prompt_text,
                    reasoning_text=reasoning_text,
                    source="cached_parser",
                )
            except Exception as error:
                last_error = str(error)
            else:
                last_error = None
        else:
            last_error = None

        parser_path = self._build_parser_path(agent_name, schema_signature)
        if self._should_use_heuristic_parser(request_payload, response_payload):
            parser_code = self._build_fallback_parser_code(agent_name=agent_name)
            prompt_text, reasoning_text = self._write_and_validate(
                parser_path=parser_path,
                parser_code=parser_code,
                request_payload=request_payload,
                response_payload=response_payload,
            )
            self.database.upsert_parser_record(
                agent_name=agent_name,
                schema_signature=schema_signature,
                parser_path=str(parser_path),
                parser_code=parser_code,
                generator_model=MODEL_REPO_ID,
                last_validation_error=last_error,
            )
            return ParserResult(
                schema_signature=schema_signature,
                parser_path=parser_path,
                parser_code=parser_code,
                prompt_text=prompt_text,
                reasoning_text=reasoning_text,
                source="heuristic_fallback",
            )

        try:
            parser_code = self._generate_parser_code(
                agent_name=agent_name,
                request_payload=request_payload,
                response_payload=response_payload,
            )
        except Exception as generation_error:
            parser_code = self._build_fallback_parser_code(agent_name=agent_name)
            prompt_text, reasoning_text = self._write_and_validate(
                parser_path=parser_path,
                parser_code=parser_code,
                request_payload=request_payload,
                response_payload=response_payload,
            )
            self.database.upsert_parser_record(
                agent_name=agent_name,
                schema_signature=schema_signature,
                parser_path=str(parser_path),
                parser_code=parser_code,
                generator_model=MODEL_REPO_ID,
                last_validation_error=f"generation_failed: {generation_error}",
            )
            return ParserResult(
                schema_signature=schema_signature,
                parser_path=parser_path,
                parser_code=parser_code,
                prompt_text=prompt_text,
                reasoning_text=reasoning_text,
                source="heuristic_fallback",
            )

        try:
            prompt_text, reasoning_text = self._write_and_validate(
                parser_path=parser_path,
                parser_code=parser_code,
                request_payload=request_payload,
                response_payload=response_payload,
            )
            source = "generated_parser"
        except Exception as error:
            original_error = str(error)
            try:
                repaired_code = self._repair_parser_code(
                    agent_name=agent_name,
                    request_payload=request_payload,
                    response_payload=response_payload,
                    previous_code=parser_code,
                    validation_error=original_error,
                )
                prompt_text, reasoning_text = self._write_and_validate(
                    parser_path=parser_path,
                    parser_code=repaired_code,
                    request_payload=request_payload,
                    response_payload=response_payload,
                )
                parser_code = repaired_code
                last_error = original_error
                source = "repaired_parser"
            except Exception as repair_error:
                fallback_code = self._build_fallback_parser_code(agent_name=agent_name)
                prompt_text, reasoning_text = self._write_and_validate(
                    parser_path=parser_path,
                    parser_code=fallback_code,
                    request_payload=request_payload,
                    response_payload=response_payload,
                )
                parser_code = fallback_code
                last_error = f"{original_error} | repair_failed: {repair_error}"
                source = "heuristic_fallback"

        self.database.upsert_parser_record(
            agent_name=agent_name,
            schema_signature=schema_signature,
            parser_path=str(parser_path),
            parser_code=parser_code,
            generator_model=MODEL_REPO_ID,
            last_validation_error=last_error,
        )
        return ParserResult(
            schema_signature=schema_signature,
            parser_path=parser_path,
            parser_code=parser_code,
            prompt_text=prompt_text,
            reasoning_text=reasoning_text,
            source=source,
        )

    def _build_parser_path(self, agent_name: str, schema_signature: str) -> Path:
        filename = f"{slugify(agent_name)}__{schema_signature}.py"
        return self.parser_dir / filename

    def _should_use_heuristic_parser(self, request_payload: Any, response_payload: Any) -> bool:
        if isinstance(response_payload, dict) and response_payload.get("format") == "sse":
            return True
        if isinstance(request_payload, dict) and isinstance(request_payload.get("input"), list):
            return len(request_payload["input"]) > 20
        return False

    def _generate_parser_code(
        self,
        *,
        agent_name: str,
        request_payload: Any,
        response_payload: Any,
    ) -> str:
        prompt = f"""
You write Python parser modules for AI-agent proxy payloads.

Target agent: {agent_name}

Task:
- Extract the dialog prompt/context from the request payload, not only the last user message.
- Exclude system/developer instructions and top-level model instructions.
- Include prior user, assistant, tool, and function-call messages when present.
- Extract the model reasoning or assistant output from the response payload.

Return ONLY valid Python source code. Do not wrap it in Markdown fences.

Required module contract:
- Define PARSER_NAME as a string.
- Define PARSER_POLICY as the string "{PARSER_POLICY_MARKER}".
- Define extract_request_prompt(payload: dict) -> str.
- Define extract_response_reasoning(payload: dict) -> str.
- Use only the Python standard library.
- Never raise exceptions from the extractor functions. Return an empty string on failure.
- Be defensive with nested dict/list structures.
- Prefer reasoning-like fields such as reasoning, thought, analysis, summary.
- If explicit reasoning is absent, fall back to assistant content, output text, function-call justification, or function-call arguments.

Observed request payload:
{json.dumps(self._compact_for_prompt(request_payload), ensure_ascii=False, indent=2)}

Observed response payload:
{json.dumps(self._compact_for_prompt(response_payload), ensure_ascii=False, indent=2)}
""".strip()
        raw_code = self._generate_response(
            prompt,
            system_prompt="You generate strict Python source code only.",
            max_tokens=1200,
            temperature=0.1,
        )
        return self._sanitize_code(raw_code)

    def _repair_parser_code(
        self,
        *,
        agent_name: str,
        request_payload: Any,
        response_payload: Any,
        previous_code: str,
        validation_error: str,
    ) -> str:
        prompt = f"""
The previous parser module for agent {agent_name} failed validation.

Validation error:
{validation_error}

Previous parser code:
{previous_code}

Observed request payload:
{json.dumps(self._compact_for_prompt(request_payload), ensure_ascii=False, indent=2)}

Observed response payload:
{json.dumps(self._compact_for_prompt(response_payload), ensure_ascii=False, indent=2)}

Return ONLY corrected Python source code. Do not include explanations or Markdown fences.
The corrected code must define PARSER_POLICY = "{PARSER_POLICY_MARKER}" and extract the dialog request prompt/context without system/developer instructions.
""".strip()
        raw_code = self._generate_response(
            prompt,
            system_prompt="You repair Python parser modules and return code only.",
            max_tokens=1200,
            temperature=0.1,
        )
        return self._sanitize_code(raw_code)

    def clean_prompt_text(self, prompt_text: str) -> str:
        fallback = self._strip_system_reminders(prompt_text)
        if self._has_known_prompt_contamination(prompt_text) and fallback:
            return fallback
        try:
            cleaned = self._generate_response(
                f"""
Remove injected system/developer reminder blocks from the prompt below.

Rules:
- Preserve the user's real request and conversation context.
- Remove XML-like system reminder blocks such as <system-reminder>...</system-reminder>.
- Remove environment/date/tool availability boilerplate when it is not user-authored.
- Return ONLY the cleaned prompt text. No explanation.

Prompt:
{prompt_text}
""".strip(),
                system_prompt="You clean extracted user prompt text.",
                max_tokens=1200,
                temperature=0.0,
            ).strip()
        except Exception:
            return fallback
        cleaned = self._strip_system_reminders(cleaned)
        return cleaned or fallback

    def normalize_reasoning_text(self, response_payload: Any, reasoning_text: str) -> str:
        anthropic_text = self._extract_anthropic_stream_reasoning(response_payload)
        if not anthropic_text:
            return reasoning_text
        if self._looks_like_response_metadata(reasoning_text):
            return anthropic_text
        if len(anthropic_text) > len(reasoning_text.strip()) + 20:
            return anthropic_text
        return reasoning_text

    def _strip_system_reminders(self, prompt_text: str) -> str:
        cleaned = re.sub(
            r"<system-reminder\b[^>]*>.*?</system-reminder>",
            "",
            prompt_text,
            flags=re.DOTALL | re.IGNORECASE,
        )
        cleaned = re.sub(
            r"<local-command-caveat\b[^>]*>.*?</local-command-caveat>",
            "",
            cleaned,
            flags=re.DOTALL | re.IGNORECASE,
        )
        cleaned = re.sub(
            r"<local-command-stdout\b[^>]*>.*?</local-command-stdout>",
            "",
            cleaned,
            flags=re.DOTALL | re.IGNORECASE,
        )
        cleaned = re.sub(
            r"<local-command-stderr\b[^>]*>.*?</local-command-stderr>",
            "",
            cleaned,
            flags=re.DOTALL | re.IGNORECASE,
        )
        cleaned = re.sub(
            r"<command-(?:name|message|args)\b[^>]*>.*?</command-(?:name|message|args)>",
            "",
            cleaned,
            flags=re.DOTALL | re.IGNORECASE,
        )
        cleaned = re.sub(
            r"(?is)as you answer the user's questions, you can use the following context:.*?important:.*?(?:\n\s*\n|$)",
            "",
            cleaned,
        )
        cleaned = re.sub(r"(?m)^[ \t]+$", "", cleaned)
        cleaned = re.sub(r"[ \t]+\n", "\n", cleaned)
        return re.sub(r"\n{3,}", "\n\n", cleaned).strip()

    def _has_known_prompt_contamination(self, prompt_text: str) -> bool:
        lowered = prompt_text.lower()
        markers = (
            "<system-reminder",
            "<local-command-caveat",
            "<command-name>",
            "<command-message>",
            "<command-args>",
            "<local-command-stdout>",
            "<local-command-stderr>",
        )
        return any(marker in lowered for marker in markers)

    def _looks_like_response_metadata(self, text: str) -> bool:
        stripped = text.strip()
        if not stripped:
            return True
        lines = [line.strip() for line in stripped.splitlines() if line.strip()]
        if not lines:
            return True
        metadata_markers = {
            "message",
            "assistant",
            "standard",
            "global",
            "tool_use",
            "end_turn",
        }
        marker_hits = sum(1 for line in lines if line in metadata_markers or line.startswith("msg_"))
        if marker_hits >= max(2, len(lines) // 2):
            return True
        if len(stripped) < 160 and any(line.startswith(("claude-", "gpt-", "gemini-")) for line in lines):
            return True
        return False

    def _extract_anthropic_stream_reasoning(self, payload: Any) -> str:
        if not isinstance(payload, list):
            return ""
        parts: list[str] = []
        current_tool_name = ""
        current_tool_json: list[str] = []

        def flush_tool() -> None:
            nonlocal current_tool_name, current_tool_json
            text = "".join(current_tool_json).strip()
            if current_tool_name or text:
                if current_tool_name and text:
                    parts.append(f"{current_tool_name}: {text}")
                elif text:
                    parts.append(text)
            current_tool_name = ""
            current_tool_json = []

        for item in payload:
            if not isinstance(item, dict):
                continue
            item_type = item.get("type")
            if item_type == "content_block_start":
                flush_tool()
                block = item.get("content_block")
                if isinstance(block, dict):
                    block_type = block.get("type")
                    if block_type == "tool_use":
                        current_tool_name = str(block.get("name") or "").strip()
                        block_input = block.get("input")
                        if block_input:
                            try:
                                current_tool_json.append(json.dumps(block_input, ensure_ascii=False))
                            except TypeError:
                                current_tool_json.append(str(block_input))
                    elif block_type in {"thinking", "text"}:
                        text = block.get("thinking") or block.get("text")
                        if isinstance(text, str) and text.strip():
                            parts.append(text.strip())
                continue
            if item_type == "content_block_delta":
                delta = item.get("delta")
                if not isinstance(delta, dict):
                    continue
                text = delta.get("thinking") or delta.get("text")
                if isinstance(text, str) and text.strip():
                    parts.append(text.strip())
                partial_json = delta.get("partial_json")
                if isinstance(partial_json, str):
                    current_tool_json.append(partial_json)
                continue
            if item_type == "content_block_stop":
                flush_tool()
        flush_tool()
        return "\n".join(part for part in parts if part).strip()

    def _generate_response(
        self,
        prompt: str,
        *,
        system_prompt: str,
        max_tokens: int,
        temperature: float,
    ) -> str:
        from runGemma4 import generate_response

        return generate_response(
            prompt,
            system_prompt=system_prompt,
            max_tokens=max_tokens,
            temperature=temperature,
        )

    def _sanitize_code(self, raw_code: str) -> str:
        cleaned = raw_code.strip()
        fenced = re.search(r"```(?:python)?\s*(.*?)```", cleaned, flags=re.DOTALL | re.IGNORECASE)
        if fenced:
            cleaned = fenced.group(1).strip()
        if "extract_request_prompt" not in cleaned or "extract_response_reasoning" not in cleaned:
            raise ParserGenerationError("generated code does not implement the required parser functions")
        compile(cleaned, "<generated_parser>", "exec")
        if PARSER_POLICY_MARKER not in cleaned:
            cleaned = f'PARSER_POLICY = "{PARSER_POLICY_MARKER}"\n' + cleaned
        return cleaned + "\n"

    def _compact_for_prompt(self, value: Any, *, max_depth: int = 4, max_list_items: int = 3, max_string: int = 300) -> Any:
        if isinstance(value, dict) and value.get("format") == "sse":
            return self._compact_sse_payload(value, max_string=max_string)
        if isinstance(value, dict) and "input" in value and isinstance(value.get("input"), list):
            return self._compact_request_payload(value, max_string=max_string)
        if max_depth <= 0:
            return f"<{type(value).__name__}>"
        if isinstance(value, str):
            if len(value) <= max_string:
                return value
            return f"{value[:max_string]}...<truncated {len(value) - max_string} chars>"
        if isinstance(value, list):
            compacted = [
                self._compact_for_prompt(item, max_depth=max_depth - 1, max_list_items=max_list_items, max_string=max_string)
                for item in value[:max_list_items]
            ]
            if len(value) > max_list_items:
                compacted.append(f"<truncated {len(value) - max_list_items} list items>")
            return compacted
        if isinstance(value, dict):
            priority_keys = (
                "format",
                "model",
                "input",
                "messages",
                "role",
                "type",
                "content",
                "text",
                "prompt",
                "instructions",
                "event_types",
                "response",
                "output_items",
                "function_calls",
                "function_call_arguments",
                "assistant_text",
                "reasoning_summaries",
                "text_candidates",
                "name",
                "arguments",
                "parsed_arguments",
                "justification",
                "raw_text",
            )
            ordered_keys = [key for key in priority_keys if key in value]
            ordered_keys.extend(key for key in value if key not in ordered_keys)
            compacted_dict: dict[str, Any] = {}
            for key in ordered_keys[:30]:
                if key in {"raw_text", "encrypted_content"}:
                    raw_value = value.get(key)
                    if isinstance(raw_value, str):
                        compacted_dict[key] = f"<{len(raw_value)} chars omitted>"
                    else:
                        compacted_dict[key] = f"<{type(raw_value).__name__} omitted>"
                    continue
                compacted_dict[key] = self._compact_for_prompt(
                    value[key],
                    max_depth=max_depth - 1,
                    max_list_items=max_list_items,
                    max_string=max_string,
                )
            if len(value) > len(compacted_dict):
                compacted_dict["_omitted_keys"] = len(value) - len(compacted_dict)
            return compacted_dict
        return value

    def _compact_request_payload(self, payload: dict[str, Any], *, max_string: int) -> dict[str, Any]:
        messages: list[dict[str, Any]] = []
        for item in payload.get("input", []):
            if not isinstance(item, dict):
                continue
            role = item.get("role")
            item_type = item.get("type")
            content_text = self._extract_text_preview(item.get("content"), max_string=max_string)
            if content_text:
                messages.append(
                    {
                        "type": item_type,
                        "role": role,
                        "content_text": content_text,
                    }
                )

        user_messages = [message for message in messages if message.get("role") == "user"]
        preview_messages = user_messages[-5:] or messages[-5:]
        return {
            "model": payload.get("model"),
            "top_level_keys": list(payload.keys()),
            "input_shape": "list of message/reasoning/tool items",
            "message_count": len(messages),
            "recent_messages": preview_messages,
        }

    def _compact_sse_payload(self, payload: dict[str, Any], *, max_string: int) -> dict[str, Any]:
        function_calls = []
        for item in payload.get("function_calls", [])[:3]:
            if not isinstance(item, dict):
                continue
            function_calls.append(
                {
                    "type": item.get("type"),
                    "name": item.get("name"),
                    "status": item.get("status"),
                    "arguments": self._truncate(item.get("arguments"), max_string),
                    "parsed_arguments": self._compact_for_prompt(
                        item.get("parsed_arguments", {}),
                        max_depth=2,
                        max_list_items=3,
                        max_string=max_string,
                    ),
                }
            )

        function_argument_events = []
        for item in payload.get("function_call_arguments", [])[:3]:
            if not isinstance(item, dict):
                continue
            function_argument_events.append(
                {
                    "type": item.get("type"),
                    "arguments": self._truncate(item.get("arguments"), max_string),
                    "parsed_arguments": self._compact_for_prompt(
                        item.get("parsed_arguments", {}),
                        max_depth=2,
                        max_list_items=3,
                        max_string=max_string,
                    ),
                }
            )

        return {
            "format": "sse",
            "event_types": payload.get("event_types"),
            "assistant_text": self._truncate(payload.get("assistant_text"), max_string),
            "reasoning_summaries": [
                self._truncate(summary, max_string)
                for summary in payload.get("reasoning_summaries", [])[:3]
            ],
            "text_candidates": [
                self._truncate(candidate, max_string)
                for candidate in payload.get("text_candidates", [])[:5]
            ],
            "function_calls": function_calls,
            "function_call_arguments": function_argument_events,
        }

    def _extract_text_preview(self, value: Any, *, max_string: int) -> str:
        if isinstance(value, str):
            return self._truncate(value, max_string)
        if isinstance(value, list):
            parts = []
            for item in value:
                if isinstance(item, dict):
                    text = item.get("text") or item.get("content")
                    if isinstance(text, str) and text.strip():
                        parts.append(text.strip())
                elif isinstance(item, str) and item.strip():
                    parts.append(item.strip())
            return self._truncate("\n".join(parts), max_string)
        if isinstance(value, dict):
            text = value.get("text") or value.get("content")
            if isinstance(text, str):
                return self._truncate(text, max_string)
        return ""

    def _truncate(self, value: Any, max_string: int) -> Any:
        if not isinstance(value, str):
            return value
        if len(value) <= max_string:
            return value
        return f"{value[:max_string]}...<truncated {len(value) - max_string} chars>"

    def _build_fallback_parser_code(self, *, agent_name: str) -> str:
        parser_name = f"{agent_name}-heuristic-fallback"
        return dedent(
            f'''
            PARSER_NAME = {parser_name!r}
            PARSER_POLICY = {PARSER_POLICY_MARKER!r}


            def _join(parts):
                return "\\n".join(part for part in parts if part).strip()


            def _collect_text(value):
                if isinstance(value, str):
                    return value.strip()
                if isinstance(value, list):
                    return _join(_collect_text(item) for item in value)
                if isinstance(value, dict):
                    preferred_keys = (
                        "summary",
                        "text",
                        "content",
                        "message",
                        "output_text",
                        "justification",
                        "arguments",
                        "raw_text",
                    )
                    for key in preferred_keys:
                        if key in value:
                            text = _collect_text(value.get(key))
                            if text:
                                return text
                    return _join(_collect_text(item) for item in value.values())
                return ""


            def _find_role_content(value, roles):
                matches = _find_all_role_content(value, roles)
                return matches[-1] if matches else ""


            def _find_all_role_content(value, roles):
                matches = []
                if isinstance(value, dict):
                    role = value.get("role")
                    if isinstance(role, str) and role.lower() in roles:
                        text = _collect_text(value.get("content") or value.get("text") or value.get("message"))
                        if text:
                            matches.append(text)
                    for nested in value.values():
                        matches.extend(_find_all_role_content(nested, roles))
                elif isinstance(value, list):
                    for item in value:
                        matches.extend(_find_all_role_content(item, roles))
                return matches


            def _format_prompt_entry(role, text, index=None):
                role_label = str(role or "unknown").strip() or "unknown"
                prefix = f"[{{role_label}}]"
                if index is not None:
                    prefix = f"{{prefix}} #{{index}}"
                return f"{{prefix}}\\n{{text.strip()}}" if text and text.strip() else ""


            def _extract_full_prompt_from_input(payload):
                if not isinstance(payload, dict):
                    return ""

                entries = []
                input_items = payload.get("input")
                if isinstance(input_items, list):
                    for index, item in enumerate(input_items):
                        if not isinstance(item, dict):
                            continue
                        item_type = item.get("type")
                        role = item.get("role") or item_type
                        role_label = str(role or "").lower()

                        if role_label in {{"system", "developer", "instructions"}}:
                            continue

                        if item_type == "reasoning" and not item.get("summary") and not item.get("content"):
                            continue

                        text = _collect_text(
                            item.get("content")
                            or item.get("text")
                            or item.get("message")
                            or item.get("summary")
                            or item.get("arguments")
                        )
                        if text:
                            entries.append(_format_prompt_entry(role, text, index))

                messages = payload.get("messages")
                if isinstance(messages, list):
                    for index, message in enumerate(messages):
                        if not isinstance(message, dict):
                            continue
                        role = message.get("role")
                        role_label = str(role or "").lower()
                        if role_label in {{"system", "developer", "instructions"}}:
                            continue
                        text = _collect_text(message.get("content") or message.get("text") or message.get("message"))
                        if text:
                            entries.append(_format_prompt_entry(role, text, index))

                return _join(entries)


            def _find_type_content(value, types):
                if isinstance(value, dict):
                    item_type = value.get("type")
                    if isinstance(item_type, str) and item_type.lower() in types:
                        return _collect_text(
                            value.get("summary")
                            or value.get("content")
                            or value.get("text")
                            or value.get("message")
                            or value.get("arguments")
                        )
                    for nested in value.values():
                        text = _find_type_content(nested, types)
                        if text:
                            return text
                elif isinstance(value, list):
                    for item in value:
                        text = _find_type_content(item, types)
                        if text:
                            return text
                return ""


            def _find_preferred_key(value, keys):
                if isinstance(value, dict):
                    for key in keys:
                        if key in value:
                            text = _collect_text(value.get(key))
                            if text:
                                return text
                    for nested in value.values():
                        text = _find_preferred_key(nested, keys)
                        if text:
                            return text
                elif isinstance(value, list):
                    for item in value:
                        text = _find_preferred_key(item, keys)
                        if text:
                            return text
                return ""


            def extract_request_prompt(payload: dict) -> str:
                try:
                    prompt = _extract_full_prompt_from_input(payload)
                    if prompt:
                        return prompt
                    prompt = _join(_find_all_role_content(payload, {{"user", "human", "assistant", "tool", "function_call"}}))
                    if prompt:
                        return prompt
                    return _find_preferred_key(
                        payload,
                        ("prompt", "input", "instruction", "question", "content", "text"),
                    )
                except Exception:
                    return ""


            def extract_response_reasoning(payload: dict) -> str:
                try:
                    reasoning = _find_type_content(payload, {{"reasoning", "analysis", "thought", "summary"}})
                    if reasoning:
                        return reasoning
                    reasoning = _find_type_content(payload, {{"function_call", "tool_call"}})
                    if reasoning:
                        return reasoning
                    reasoning = _find_preferred_key(
                        payload,
                        ("reasoning", "analysis", "thought", "summary", "justification", "arguments"),
                    )
                    if reasoning:
                        return reasoning
                    assistant = _find_role_content(payload, {{"assistant", "model"}})
                    if assistant:
                        return assistant
                    return _find_preferred_key(
                        payload,
                        ("output_text", "text", "content", "message", "raw_text"),
                    )
                except Exception:
                    return ""
            '''
        ).strip() + "\n"

    def _write_and_validate(
        self,
        *,
        parser_path: Path,
        parser_code: str,
        request_payload: Any,
        response_payload: Any,
    ) -> tuple[str, str]:
        parser_path.write_text(parser_code, encoding="utf-8")
        return self._validate_parser(
            parser_path=parser_path,
            request_payload=request_payload,
            response_payload=response_payload,
        )

    def _validate_parser(
        self,
        *,
        parser_path: Path,
        request_payload: Any,
        response_payload: Any,
    ) -> tuple[str, str]:
        module_name = f"generated_parser_{parser_path.stem}"
        spec = importlib.util.spec_from_file_location(module_name, parser_path)
        if spec is None or spec.loader is None:
            raise ParserGenerationError(f"failed to load parser module: {parser_path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        request_fn = getattr(module, "extract_request_prompt", None)
        response_fn = getattr(module, "extract_response_reasoning", None)
        if request_fn is None or response_fn is None:
            raise ParserGenerationError("parser module is missing required extractor functions")

        prompt_text = str(request_fn(request_payload) or "").strip()
        reasoning_text = str(response_fn(response_payload) or "").strip()
        if not prompt_text:
            raise ParserGenerationError("parser returned an empty prompt")
        self._validate_full_prompt_context(request_payload, prompt_text)
        if not reasoning_text:
            raise ParserGenerationError("parser returned an empty reasoning/output field")
        return prompt_text, reasoning_text

    def _validate_full_prompt_context(self, request_payload: Any, prompt_text: str) -> None:
        message_texts = self._collect_request_message_texts(request_payload)
        if not message_texts:
            return

        meaningful_messages = [
            text
            for role, text in message_texts
            if role in {"user", "human", "assistant", "tool"}
        ]
        candidates = meaningful_messages or [text for _, text in message_texts]
        for text in candidates:
            normalized = text.strip()
            if len(normalized) > 120:
                normalized = normalized[:120]
            if normalized and normalized in prompt_text:
                return

        raise ParserGenerationError("parser did not include request message history in prompt_text")

    def _collect_request_message_texts(self, value: Any) -> list[tuple[str, str]]:
        messages: list[tuple[str, str]] = []
        if isinstance(value, dict):
            role = value.get("role")
            if isinstance(role, str):
                text = self._extract_request_text(value.get("content") or value.get("text") or value.get("message"))
                if text:
                    messages.append((role.lower(), text))
            for nested in value.values():
                messages.extend(self._collect_request_message_texts(nested))
        elif isinstance(value, list):
            for item in value:
                messages.extend(self._collect_request_message_texts(item))
        return messages

    def _extract_request_text(self, value: Any) -> str:
        if isinstance(value, str):
            return value.strip()
        if isinstance(value, list):
            parts = []
            for item in value:
                text = self._extract_request_text(item)
                if text:
                    parts.append(text)
            return "\n".join(parts).strip()
        if isinstance(value, dict):
            return self._extract_request_text(value.get("text") or value.get("content") or value.get("message"))
        return ""
