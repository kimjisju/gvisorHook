# SLLM Syscall Normalization Pipeline

This repository builds a pipeline that stores:

- proxy-hooked LLM request payloads
- proxy-hooked LLM response payloads
- gVisor-hooked syscalls

as per-event JSON files for host-OS impact analysis.

## What It Does

1. Receives `agent_name`, `request`, `response`, and `syscall`.
2. Reuses a saved parser for the same `agent_name + schema signature` when possible.
3. If no parser exists, generates one with Gemma using `runGemma4.py`.
4. If the generated parser still fails, retries once with Gemma repair.
5. If that also fails, saves a heuristic fallback parser so the pipeline can keep running.
6. Stores normalized event data as one JSON file per event.

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
  SQLite-backed parser cache.
- `structured_pipeline/schema.py`
  Schema signature and syscall-name extraction helpers.
- `generated_parsers/`
  Saved agent-specific parser modules.
- `data/events/`
  Default output directory for normalized per-event JSON files.

## Storage

- `parser_registry`
  Stores generated parser code by `agent_name + schema_signature`.
- Event JSON files
  Store `syscall`, `summary`, `path`, `argv`, `prompt_text`, `reasoning_text`, and creation time.

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
./venv/bin/python pipeline.py --event-file examples/sample_event.json --event-output-dir data/events
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

- Request files can be JSON. Response files can be JSON or SSE-style `event:` / `data:` streams. Syscall files can be JSON or a plain text line such as `exec_command ...`.
- The first run for a new agent schema may take longer because Gemma loads and generates parser code.
- Subsequent runs reuse the saved parser from `parser_registry`.
