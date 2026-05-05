from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from gvisor_hook.bundle import write_bundle_config
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

    def test_write_bundle_config_uses_agent_argv_and_proxy_env(self) -> None:
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
                upstream_proxy_url="http://127.0.0.1:12345",
                agent_argv=["/tmp/agent/bin/tool", "run"],
                trusted_ca_cert_path="/tmp/mitmproxy/mitmproxy-ca-cert.pem",
            )

            config = json.loads(config_path.read_text(encoding="utf-8"))
            self.assertEqual(config["process"]["args"], ["/tmp/agent/bin/tool", "run"])
            env = config["process"]["env"]
            self.assertIn("HTTP_PROXY=http://127.0.0.1:12345", env)
            self.assertIn("NODE_EXTRA_CA_CERTS=/tmp/mitmproxy/mitmproxy-ca-cert.pem", env)


if __name__ == "__main__":
    unittest.main()
