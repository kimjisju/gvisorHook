from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gvisor_hook.models import LLMExchange, SyscallEvent
from gvisor_hook.reason_pipeline import (
    ReasonPipelineConfig,
    build_pipeline_event,
    default_reason_pipeline_dir,
    write_pipeline_event,
)


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


if __name__ == "__main__":
    unittest.main()
