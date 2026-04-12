from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gvisor_hook.bundle import DATASET_PLAN_INSTRUCTIONS, write_bundle_config
from gvisor_hook.dataset import create_dataset_session, record_terminal_chunk


class DatasetCaptureTests(unittest.TestCase):
    def test_create_dataset_session_and_record_terminal_chunks(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            dataset_root = Path(tempdir)
            session = create_dataset_session(
                dataset_root,
                "session-test",
                {"container_id": "demo", "plan_mode_enabled": True},
            )

            stdin_event = record_terminal_chunk(session, stream="stdin", data=b"hello")
            stdout_event = record_terminal_chunk(session, stream="stdout", data=b"world")

            self.assertEqual(session.terminal_stdin_path.read_bytes(), b"hello")
            self.assertEqual(session.terminal_stdout_path.read_bytes(), b"world")

            manifest = json.loads(session.manifest_path.read_text(encoding="utf-8"))
            self.assertEqual(manifest["session_id"], "session-test")
            self.assertTrue(manifest["metadata"]["plan_mode_enabled"])

            terminal_lines = [
                json.loads(line)
                for line in session.terminal_log_path.read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual(len(terminal_lines), 2)
            self.assertEqual(terminal_lines[0]["stream"], "stdin")
            self.assertEqual(terminal_lines[1]["stream"], "stdout")
            self.assertEqual(stdin_event["offset"], 0)
            self.assertEqual(stdout_event["offset"], 0)

    def test_write_bundle_config_adds_profile_and_plan_instructions(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            bundle_dir = Path(tempdir) / "bundle"
            config_path = write_bundle_config(
                bundle_dir,
                workdir=Path(tempdir),
                runtime_home_dir="/tmp/oi-home",
                container_id="demo-container",
                resolv_conf_path="/tmp/resolv.conf",
                hosts_path="/tmp/hosts",
                nsswitch_conf_path="/tmp/nsswitch.conf",
                proxy_base_url="http://127.0.0.1:18080/openai/v1",
                profile="default.yaml",
                custom_instructions=DATASET_PLAN_INSTRUCTIONS,
            )

            config = json.loads(config_path.read_text(encoding="utf-8"))
            args = config["process"]["args"]
            self.assertEqual(args[:2], ["/usr/bin/python3", "/tmp/open-interpreter/bin/interpreter"])
            self.assertIn("--profile", args)
            self.assertIn("default.yaml", args)
            self.assertIn("--custom_instructions", args)
            self.assertIn(DATASET_PLAN_INSTRUCTIONS, args)


if __name__ == "__main__":
    unittest.main()
