# SLLM Syscall Normalization Pipeline

This repository builds a pipeline that stores:

- proxy-hooked LLM request payloads
- proxy-hooked LLM response payloads
- gVisor-hooked syscalls

into structured SQLite tables for host-OS impact analysis.

## What It Does

1. Receives `agent_name`, `request`, `response`, and `syscall`.
2. Checks `data/syscall_host_impact_map.csv` first.
3. Stops early when the syscall is mapped to `affects_host_os=0`.
4. Reuses a saved parser for the same `agent_name + schema signature` when possible.
5. If no parser exists, generates one with Gemma using `runGemma4.py`.
6. If the generated parser still fails, retries once with Gemma repair.
7. If that also fails, saves a heuristic fallback parser so the pipeline can keep running.
8. Stores normalized rows in SQLite.

## Files

- `runGemma4.py`
  Gemma loader and text generation helper reused by the pipeline.
- `pipeline.py`
  CLI entrypoint.
- `structured_pipeline/core.py`
  Main orchestration logic.
- `structured_pipeline/parser_manager.py`
  Parser generation, repair, validation, caching, and fallback handling.
- `structured_pipeline/db.py`
  SQLite schema and persistence logic.
- `structured_pipeline/schema.py`
  Schema signature and syscall-name extraction helpers.
- `data/syscall_host_impact_map.csv`
  Sample syscall host-impact mapping table.
- `generated_parsers/`
  Saved agent-specific parser modules.

## SQLite Tables

- `syscall_host_impact_map`
  Sample mapping table with `syscall_name`, `affects_host_os`, `category`, `rationale`.
- `parser_registry`
  Stores generated parser code by `agent_name + schema_signature`.
- `normalized_events`
  Stores `syscall_name`, `prompt_text`, `reasoning_text`, and raw payload JSON.

## Input JSON Format

```json
{
  "agent_name": "sample-openai-agent",
  "request": {},
  "response": {},
  "syscall": {}
}
```

`examples/sample_event.json` follows this format.

## Run

```bash
./venv/bin/python pipeline.py --event-file examples/sample_event.json
```

Or pass files separately:

```bash
./venv/bin/python pipeline.py \
  --agent-name my-agent \
  --request-file request.json \
  --response-file response.json \
  --syscall-file syscall.json
```

## Notes

- Unknown syscalls are treated conservatively as `affects_host_os=1`.
- Request files can be JSON. Response files can be JSON or SSE-style `event:` / `data:` streams. Syscall files can be JSON or a plain text line such as `exec_command ...`.
- The first run for a new agent schema may take longer because Gemma loads and generates parser code.
- Subsequent runs reuse the saved parser from `parser_registry`.
