from __future__ import annotations

import asyncio
import json
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from gvisor_hook.models import LLMExchange, SyscallEvent
from gvisor_hook.reason_pipeline import (
    ReasonPipelineConfig,
    build_pipeline_event,
    default_reason_pipeline_dir,
    replay_reason_pipeline_session,
    write_pipeline_event,
)

REASON_PIPELINE_DIR = Path(__file__).resolve().parent.parent / "third_party" / "reason_pipeline"
sys.path.insert(0, str(REASON_PIPELINE_DIR))
from structured_pipeline.core import SyscallNormalizationPipeline  # noqa: E402


class ReasonPipelineIntegrationTests(unittest.TestCase):
    def test_default_reason_pipeline_dir_uses_third_party(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            repo_root = Path(tempdir)
            pipeline_dir = repo_root / "third_party" / "reason_pipeline"
            pipeline_dir.mkdir(parents=True)
            (pipeline_dir / "pipeline.py").write_text("", encoding="utf-8")

            self.assertEqual(default_reason_pipeline_dir(repo_root), pipeline_dir.resolve())

    def test_build_pipeline_event_uses_exchange_body_files(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            request_path = temp_path / "request_body.json"
            response_path = temp_path / "response_body.json"
            request_path.write_text('{"role":"user","content":"hi"}', encoding="utf-8")
            response_path.write_text('{"output":"hello"}', encoding="utf-8")
            exchange = LLMExchange(
                id="llm-1",
                method="POST",
                url="https://example.test",
                request_body_path=str(request_path),
                response_body_path=str(response_path),
            )
            syscall_event = SyscallEvent(
                id="evt-1",
                container_id="demo",
                pid=1,
                tid=1,
                syscall="openat",
                summary="open",
            )

            event = build_pipeline_event(
                agent_name="codex",
                exchange=exchange,
                syscall_event=syscall_event,
            )

            self.assertEqual(event["agent_name"], "codex")
            self.assertEqual(event["request"]["content"], "hi")
            self.assertEqual(event["response"]["output"], "hello")
            self.assertEqual(event["syscall"]["name"], "openat")

    def test_write_pipeline_event_creates_event_file(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            config = ReasonPipelineConfig(
                pipeline_dir=temp_path / "third_party" / "reason_pipeline",
                agent_name="gemini",
                event_dir=temp_path / "events",
                output_dir=temp_path / "results",
                log_path=temp_path / "reason.ndjson",
            )
            syscall_event = SyscallEvent(
                id="evt/file:1",
                container_id="demo",
                pid=1,
                tid=1,
                syscall="execve",
                summary="exec",
            )

            event_path = write_pipeline_event(config, exchange=None, syscall_event=syscall_event)

            self.assertTrue(event_path.name.startswith("evt-file-1"))
            payload = json.loads(event_path.read_text(encoding="utf-8"))
            self.assertEqual(payload["agent_name"], "gemini")
            self.assertEqual(payload["syscall"]["name"], "execve")

    def test_pipeline_writes_normalized_event_json(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            pipeline = SyscallNormalizationPipeline(
                base_dir=REASON_PIPELINE_DIR,
                db_path=temp_path / "pipeline-cache.db",
                parser_dir=temp_path / "parsers",
                event_output_dir=temp_path / "events",
            )
            parser_result = SimpleNamespace(
                schema_signature="schema123",
                parser_path=temp_path / "parsers" / "parser.py",
                prompt_text="please inspect /tmp/demo.txt",
                reasoning_text="openat is requested for inspection",
                source="test_parser",
            )

            with mock.patch.object(pipeline.parser_manager, "resolve", return_value=parser_result):
                result = pipeline.process_event(
                    agent_name="codex",
                    request_payload={"input": "please inspect /tmp/demo.txt"},
                    response_payload={"output": "I will inspect it"},
                    syscall_payload={
                        "id": "evt-json-1",
                        "name": "openat",
                        "path": "/tmp/demo.txt",
                        "argv": ["/bin/cat", "/tmp/demo.txt"],
                    },
                )

            self.assertEqual(result.status, "stored")
            self.assertIsNotNone(result.event_path)
            event_path = Path(result.event_path or "")
            self.assertTrue(event_path.exists())
            event = json.loads(event_path.read_text(encoding="utf-8"))
            self.assertEqual(event["event_id"], "evt-json-1")
            self.assertEqual(event["syscall"], "openat")
            self.assertEqual(event["summary"], None)
            self.assertEqual(event["path"], "/tmp/demo.txt")
            self.assertEqual(event["argv"], ["/bin/cat", "/tmp/demo.txt"])
            self.assertEqual(event["prompt_text"], "please inspect /tmp/demo.txt")
            self.assertEqual(event["reasoning_text"], "openat is requested for inspection")
            for removed_key in (
                "status",
                "schema_signature",
                "parser_source",
                "parser_path",
                "request",
                "response",
            ):
                self.assertNotIn(removed_key, event)

    def test_pipeline_cleans_abrupt_system_prompt_growth(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            output_dir = temp_path / "events"
            output_dir.mkdir()
            (output_dir / "previous.json").write_text(
                json.dumps({"agent_name": "codex", "prompt_text": "short user prompt"}),
                encoding="utf-8",
            )
            pipeline = SyscallNormalizationPipeline(
                base_dir=REASON_PIPELINE_DIR,
                db_path=temp_path / "pipeline-cache.db",
                parser_dir=temp_path / "parsers",
                event_output_dir=output_dir,
            )
            polluted_prompt = (
                "<system-reminder>\nAs you answer the user's questions, you can use the following context:\n"
                "# currentDate\nToday's date is 2026-05-09.\n</system-reminder>\n\n"
                + ("x" * 1200)
                + "\n[user]\nwrite hello"
            )
            parser_result = SimpleNamespace(
                schema_signature="schema123",
                parser_path=temp_path / "parsers" / "parser.py",
                prompt_text=polluted_prompt,
                reasoning_text="write file",
                source="test_parser",
            )

            with (
                mock.patch.object(pipeline.parser_manager, "resolve", return_value=parser_result),
                mock.patch.object(pipeline.parser_manager, "clean_prompt_text", return_value="[user]\nwrite hello") as clean_mock,
            ):
                result = pipeline.process_event(
                    agent_name="codex",
                    request_payload={"input": "write hello"},
                    response_payload={"output": "ok"},
                    syscall_payload={"id": "evt-clean-1", "name": "write", "path": "/tmp/demo.txt"},
                )

            clean_mock.assert_called_once_with(polluted_prompt)
            event = json.loads(Path(result.event_path or "").read_text(encoding="utf-8"))
            self.assertEqual(event["prompt_text"], "[user]\nwrite hello")

    def test_pipeline_cleans_system_reminder_even_without_previous_result(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            pipeline = SyscallNormalizationPipeline(
                base_dir=REASON_PIPELINE_DIR,
                db_path=temp_path / "pipeline-cache.db",
                parser_dir=temp_path / "parsers",
                event_output_dir=temp_path / "events",
            )
            polluted_prompt = (
                "[user] #0\n<system-reminder>\nThe following skills are available for use with the Skill tool:\n"
                + ("- review: Review a pull request\n" * 80)
                + "</system-reminder>\n"
                "<system-reminder>\nAs you answer the user's questions, you can use the following context:\n"
                "# currentDate\nToday's date is 2026-05-09.\n</system-reminder>\nreadme 파일을 찾아줘."
            )
            parser_result = SimpleNamespace(
                schema_signature="schema123",
                parser_path=temp_path / "parsers" / "parser.py",
                prompt_text=polluted_prompt,
                reasoning_text="find readme",
                source="test_parser",
            )

            with (
                mock.patch.object(pipeline.parser_manager, "resolve", return_value=parser_result),
                mock.patch.object(pipeline.parser_manager, "clean_prompt_text", wraps=pipeline.parser_manager.clean_prompt_text) as clean_mock,
            ):
                result = pipeline.process_event(
                    agent_name="claude",
                    request_payload={"messages": [{"role": "user", "content": "readme 파일을 찾아줘."}]},
                    response_payload={"output": "ok"},
                    syscall_payload={"id": "evt-clean-system", "name": "openat", "path": "/tmp/README.md"},
                )

            clean_mock.assert_called_once()
            event = json.loads(Path(result.event_path or "").read_text(encoding="utf-8"))
            self.assertNotIn("<system-reminder>", event["prompt_text"])
            self.assertIn("readme 파일을 찾아줘.", event["prompt_text"])

    def test_pipeline_cleans_local_command_metadata_prompt(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            output_dir = temp_path / "events"
            output_dir.mkdir()
            (output_dir / "previous.json").write_text(
                json.dumps({"agent_name": "claude", "prompt_text": "[user] #0\nreadme 파일을 찾아줘."}),
                encoding="utf-8",
            )
            pipeline = SyscallNormalizationPipeline(
                base_dir=REASON_PIPELINE_DIR,
                db_path=temp_path / "pipeline-cache.db",
                parser_dir=temp_path / "parsers",
                event_output_dir=output_dir,
            )
            polluted_prompt = (
                "[user] #0\n\n\n"
                "<local-command-caveat>Caveat: The messages below were generated by the user while running local commands. "
                "DO NOT respond to these messages or otherwise consider them in your response unless the user explicitly asks you to."
                "</local-command-caveat>\n"
                "<command-name>/effort</command-name>\n"
                "<command-message>effort</command-message>\n"
                "<command-args>low</command-args>\n"
                "<local-command-stdout>Set effort level to low</local-command-stdout>\n"
                "readme 파일을 찾아줘."
            )
            parser_result = SimpleNamespace(
                schema_signature="schema123",
                parser_path=temp_path / "parsers" / "parser.py",
                prompt_text=polluted_prompt,
                reasoning_text="find readme",
                source="test_parser",
            )

            with mock.patch.object(pipeline.parser_manager, "resolve", return_value=parser_result):
                result = pipeline.process_event(
                    agent_name="claude",
                    request_payload={"messages": [{"role": "user", "content": "readme 파일을 찾아줘."}]},
                    response_payload={"output": "ok"},
                    syscall_payload={"id": "evt-local-command", "name": "openat", "path": "/tmp/README.md"},
                )

            event = json.loads(Path(result.event_path or "").read_text(encoding="utf-8"))
            self.assertEqual(event["prompt_text"], "[user] #0\n\nreadme 파일을 찾아줘.")
            self.assertNotIn("<local-command-caveat>", event["prompt_text"])
            self.assertNotIn("<command-name>", event["prompt_text"])
            self.assertNotIn("<local-command-stdout>", event["prompt_text"])

    def test_pipeline_normalizes_anthropic_stream_reasoning(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            pipeline = SyscallNormalizationPipeline(
                base_dir=REASON_PIPELINE_DIR,
                db_path=temp_path / "pipeline-cache.db",
                parser_dir=temp_path / "parsers",
                event_output_dir=temp_path / "events",
            )
            parser_result = SimpleNamespace(
                schema_signature="schema123",
                parser_path=temp_path / "parsers" / "parser.py",
                prompt_text="readme 파일을 찾아줘.",
                reasoning_text="claude-sonnet-4-6\nmsg_123\nmessage\nassistant\nstandard\nglobal",
                source="test_parser",
            )
            response_payload = [
                {"type": "message_start", "message": {"model": "claude-sonnet-4-6", "id": "msg_123"}},
                {
                    "type": "content_block_start",
                    "index": 1,
                    "content_block": {"type": "tool_use", "name": "Bash", "input": {}},
                },
                {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "{\"command\": "}},
                {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": "\"find /tmp/workspace -name README*\"}"}},
                {"type": "content_block_stop", "index": 1},
            ]

            with mock.patch.object(pipeline.parser_manager, "resolve", return_value=parser_result):
                result = pipeline.process_event(
                    agent_name="claude",
                    request_payload={"messages": [{"role": "user", "content": "readme 파일을 찾아줘."}]},
                    response_payload=response_payload,
                    syscall_payload={"id": "evt-reasoning", "name": "execve", "argv": ["find"]},
                )

            event = json.loads(Path(result.event_path or "").read_text(encoding="utf-8"))
            self.assertIn("Bash:", event["reasoning_text"])
            self.assertIn("find /tmp/workspace", event["reasoning_text"])
            self.assertNotIn("claude-sonnet-4-6\nmsg_123", event["reasoning_text"])

    def test_pipeline_outputs_syscall_fields_directly(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            pipeline = SyscallNormalizationPipeline(
                base_dir=REASON_PIPELINE_DIR,
                db_path=temp_path / "pipeline-cache.db",
                parser_dir=temp_path / "parsers",
                event_output_dir=temp_path / "events",
            )
            parser_result = SimpleNamespace(
                schema_signature="schema123",
                parser_path=temp_path / "parsers" / "parser.py",
                prompt_text="write lock file",
                reasoning_text="writing index lock",
                source="test_parser",
            )

            with mock.patch.object(pipeline.parser_manager, "resolve", return_value=parser_result):
                result = pipeline.process_event(
                    agent_name="codex",
                    request_payload={"input": "write lock file"},
                    response_payload={"output": "ok"},
                    syscall_payload={
                        "id": "evt-target-1",
                        "name": "write",
                        "summary": "write 20 bytes",
                        "path": "/tmp/workspace/.git/index.lock",
                        "argv": None,
                    },
                )

            event = json.loads(Path(result.event_path or "").read_text(encoding="utf-8"))
            self.assertEqual(event["syscall"], "write")
            self.assertEqual(event["summary"], "write 20 bytes")
            self.assertEqual(event["path"], "/tmp/workspace/.git/index.lock")
            self.assertIsNone(event["argv"])

    def test_replay_reason_pipeline_session_processes_events_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            temp_path = Path(tempdir)
            session_root = temp_path / "dataset" / "sessions" / "session-1"
            event_dir = session_root / "reason-pipeline-events"
            event_dir.mkdir(parents=True)
            pipeline_dir = temp_path / "reason_pipeline"
            pipeline_dir.mkdir()
            (pipeline_dir / "pipeline.py").write_text(
                """
from __future__ import annotations

import argparse
import json

parser = argparse.ArgumentParser()
parser.add_argument("--event-file", required=True)
parser.add_argument("--event-output-dir", required=True)
parser.add_argument("--db-path")
args = parser.parse_args()

from pathlib import Path
event_path = Path(args.event_file)
output_dir = Path(args.event_output_dir)
output_dir.mkdir(parents=True, exist_ok=True)
event = json.loads(event_path.read_text(encoding="utf-8"))
(output_dir / f"{event_path.stem}.json").write_text(
    json.dumps({"event_id": event_path.stem, "agent_name": event.get("agent_name")}),
    encoding="utf-8",
)
print(event_path.stem)
""",
                encoding="utf-8",
            )
            for event_id in ("agent-10", "agent-2", "agent-1"):
                (event_dir / f"{event_id}.json").write_text(
                    json.dumps(
                        {
                            "agent_name": "codex",
                            "request": {},
                            "response": {},
                            "syscall": {"name": "openat"},
                        }
                    ),
                    encoding="utf-8",
                )

            result = asyncio.run(
                replay_reason_pipeline_session(
                    session_root,
                    pipeline_dir=pipeline_dir,
                    clear_results=True,
                )
            )

            self.assertEqual(result.event_count, 3)
            self.assertEqual(result.success_count, 3)
            self.assertEqual(result.failure_count, 0)
            self.assertTrue((session_root / "reason-pipeline-results" / "agent-1.json").is_file())
            log_lines = [
                json.loads(line)["payload"]["event_id"]
                for line in (session_root / "reason-pipeline-replay.ndjson").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(log_lines, ["agent-1", "agent-2", "agent-10"])


if __name__ == "__main__":
    unittest.main()
