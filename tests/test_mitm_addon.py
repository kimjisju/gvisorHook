from __future__ import annotations

import importlib
import gzip
import json
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock


class FakeHeaders:
    def __init__(self, values: dict[str, str] | None = None) -> None:
        self.values = {key.lower(): value for key, value in (values or {}).items()}
        self.fields = [
            (key.encode("utf-8"), value.encode("utf-8"))
            for key, value in self.values.items()
        ]

    def get(self, key: str, default: str = "") -> str:
        return self.values.get(key.lower(), default)


class MitmAddonFilterTests(unittest.TestCase):
    def load_addon(self, tempdir: str, *, target_hosts: str = ""):
        fake_http = types.SimpleNamespace(
            Message=object,
            Request=object,
            Response=object,
            HTTPFlow=object,
        )
        fake_mitmproxy = types.ModuleType("mitmproxy")
        fake_mitmproxy.http = fake_http

        sys.modules.pop("gvisor_hook.mitm_addon", None)
        sys.modules["mitmproxy"] = fake_mitmproxy
        sys.modules["mitmproxy.http"] = fake_http

        session_root = Path(tempdir) / "dataset" / "sessions" / "session-test"
        env = {
            "GVISOR_HOOK_LLM_LOG_PATH": str(session_root / "llm" / "ui.ndjson"),
            "GVISOR_HOOK_DATASET_SESSION_DIR": str(session_root),
            "GVISOR_HOOK_DATASET_ROOT": str(session_root.parent.parent),
            "GVISOR_HOOK_SESSION_ID": "session-test",
            "GVISOR_HOOK_LLM_TARGET_HOSTS": target_hosts,
        }
        with mock.patch.dict("os.environ", env, clear=False):
            return importlib.import_module("gvisor_hook.mitm_addon")

    def fake_flow(
        self,
        addon,
        body: bytes,
        *,
        host: str = "api.example.test",
        request_headers: dict[str, str] | None = None,
        response_headers: dict[str, str] | None = None,
    ):
        headers = FakeHeaders(request_headers)
        response_headers = FakeHeaders(response_headers)
        request = types.SimpleNamespace(
            raw_content=body,
            pretty_host=host,
            method="POST",
            path="/v1/test",
            pretty_url=f"https://{host}/v1/test",
            http_version="HTTP/1.1",
            headers=headers,
        )
        response = types.SimpleNamespace(
            raw_content=b"ok",
            status_code=200,
            reason="OK",
            http_version="HTTP/1.1",
            headers=response_headers,
        )
        return types.SimpleNamespace(
            id="flow-test",
            request=request,
            response=response,
            metadata={},
            error=None,
            websocket=types.SimpleNamespace(messages=[]),
        )

    def fake_websocket_flow(self, http_flow, messages):
        return types.SimpleNamespace(
            id="websocket-flow-test",
            handshake_flow=http_flow,
            messages=messages,
            metadata={},
        )

    def test_should_capture_all_requests_without_host_filter(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)

            self.assertTrue(addon.should_capture(self.fake_flow(addon, b'{"ordinary": "payload"}')))
            self.assertTrue(addon.should_capture(self.fake_flow(addon, b"")))

    def test_should_capture_honors_target_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir, target_hosts="capture.example.test")

            self.assertTrue(
                addon.should_capture(
                    self.fake_flow(addon, b'{"tools": []}', host="capture.example.test")
                )
            )
            self.assertFalse(
                addon.should_capture(
                    self.fake_flow(addon, b'{"tools": []}', host="skip.example.test")
                )
            )

    def test_should_persist_body_matches_markers_case_and_spacing_insensitive(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)

            self.assertTrue(addon.should_persist_body(b'{"tools": []}'))
            self.assertTrue(addon.should_persist_body(b'{"ROLE": "user"}'))
            self.assertTrue(addon.should_persist_body(b'{"system Instruction": {}}'))
            self.assertFalse(addon.should_persist_body(b'{"user": "too broad"}'))
            self.assertFalse(addon.should_persist_body(b'{"messages": []}'))
            self.assertFalse(addon.should_persist_body(b'{"numAllowedTools": 0}'))
            self.assertFalse(addon.should_persist_body(b'{"label": "deferred_tools_delta"}'))
            self.assertFalse(addon.should_persist_body(b'{"ordinary": "payload"}'))
            self.assertFalse(addon.should_persist_body(b""))

    def test_response_persists_only_successful_non_empty_statuses(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)

            allowed = self.fake_flow(addon, b'{"role":"user","content":"request"}')
            allowed.response.status_code = 200
            with mock.patch.object(addon, "persist_flow") as persist_mock:
                addon.response(allowed)
            persist_mock.assert_called_once()

            for status_code in (204, 301, 302, 400, 404, 500, 503):
                flow = self.fake_flow(addon, b"request")
                flow.response.status_code = status_code
                with mock.patch.object(addon, "persist_flow") as persist_mock:
                    addon.response(flow)
                persist_mock.assert_not_called()

            unmarked = self.fake_flow(addon, b'{"ordinary":"payload"}')
            unmarked.response.status_code = 200
            with mock.patch.object(addon, "persist_flow") as persist_mock:
                addon.response(unmarked)
            persist_mock.assert_not_called()

    def test_request_and_error_do_not_persist_pending_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)
            flow = self.fake_flow(addon, b"request")

            with mock.patch.object(addon, "persist_flow") as persist_mock:
                addon.request(flow)
                addon.error(flow)

            persist_mock.assert_not_called()
            self.assertIn("gvisor_hook_started_at", flow.metadata)

    def test_http_artifact_name_uses_request_order_prefix(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)
            first = self.fake_flow(addon, b'{"role":"user","content":"first"}')
            first.id = "first-flow"
            second = self.fake_flow(addon, b'{"role":"user","content":"second"}')
            second.id = "second-flow"

            addon.request(first)
            addon.request(second)
            addon.response(second)
            addon.response(first)

            llm_dir = Path(tempdir) / "dataset" / "sessions" / "session-test" / "llm"
            self.assertTrue((llm_dir / "000001_first-flow").is_dir())
            self.assertTrue((llm_dir / "000002_second-flow").is_dir())

    def test_http_bodies_are_decompressed_and_saved_as_json(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)
            flow = self.fake_flow(
                addon,
                gzip.compress(b'{"role":"user","content":"compressed request"}'),
                request_headers={"content-encoding": "gzip", "content-type": "application/json"},
                response_headers={"content-encoding": "gzip", "content-type": "application/json"},
            )
            flow.id = "gzip-flow"
            flow.response.raw_content = gzip.compress(b'{"ok":true}')

            addon.request(flow)
            addon.response(flow)

            artifact_dir = Path(tempdir) / "dataset" / "sessions" / "session-test" / "llm" / "000001_gzip-flow"
            self.assertEqual(
                json.loads((artifact_dir / "request_body.json").read_text(encoding="utf-8")),
                {"role": "user", "content": "compressed request"},
            )
            self.assertEqual(
                json.loads((artifact_dir / "response_body.json").read_text(encoding="utf-8")),
                {"ok": True},
            )
            self.assertTrue((artifact_dir / "request_headers.raw").is_file())
            self.assertTrue((artifact_dir / "response_headers.raw").is_file())

    def test_sse_body_is_saved_as_json_array(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)
            flow = self.fake_flow(
                addon,
                b'{"role":"user","content":"stream"}',
                request_headers={"content-type": "application/json"},
                response_headers={"content-type": "text/event-stream"},
            )
            flow.id = "sse-flow"
            flow.response.raw_content = (
                b'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"hello"}]}}]}}\r\n\r\n'
                b'data: {"response":{"candidates":[{"content":{"role":"model","parts":[{"text":" world"}]}}]}}\r\n\r\n'
                b"data: [DONE]\r\n\r\n"
            )

            addon.request(flow)
            addon.response(flow)

            artifact_dir = Path(tempdir) / "dataset" / "sessions" / "session-test" / "llm" / "000001_sse-flow"
            response_body = json.loads((artifact_dir / "response_body.json").read_text(encoding="utf-8"))
            self.assertEqual(response_body[0]["response"]["candidates"][0]["content"]["parts"][0]["text"], "hello")
            self.assertEqual(response_body[1]["response"]["candidates"][0]["content"]["parts"][0]["text"], " world")

    def test_websocket_message_persists_turn_transcripts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)
            handshake = self.fake_flow(addon, b"handshake")
            handshake.response.status_code = 101
            first_messages = [
                types.SimpleNamespace(
                    from_client=True,
                    content='{"model":"gpt-test","role":"user","input":"hello"}',
                    timestamp=1777906110.0,
                ),
                types.SimpleNamespace(
                    from_client=False,
                    content='{"type":"response.output_text.delta","delta":"hi"}',
                    timestamp=1777906111.0,
                ),
            ]
            flow = self.fake_websocket_flow(
                handshake,
                first_messages,
            )

            addon.websocket_message(flow)
            flow.messages.extend(
                [
                    types.SimpleNamespace(
                        from_client=True,
                        content='{"model":"gpt-test","systemInstruction":"be useful","input":"second request"}',
                        timestamp=1777906112.0,
                    ),
                    types.SimpleNamespace(
                        from_client=False,
                        content='{"type":"response.output_text.delta","delta":"second response"}',
                        timestamp=1777906113.0,
                    ),
                ]
            )
            addon.websocket_message(flow)

            first_artifact_dir = (
                Path(tempdir)
                / "dataset"
                / "sessions"
                / "session-test"
                / "llm"
                / "000001_websocket-flow-test-websocket-turn-000001"
            )
            second_artifact_dir = (
                Path(tempdir)
                / "dataset"
                / "sessions"
                / "session-test"
                / "llm"
                / "000002_websocket-flow-test-websocket-turn-000002"
            )
            request_body = json.loads((first_artifact_dir / "request_body.json").read_text(encoding="utf-8"))
            self.assertEqual(request_body[0]["body"]["input"], "hello")
            first_response = json.loads((first_artifact_dir / "response_body.json").read_text(encoding="utf-8"))
            self.assertEqual(first_response[0]["body"]["delta"], "hi")
            second_request = json.loads((second_artifact_dir / "request_body.json").read_text(encoding="utf-8"))
            self.assertEqual(second_request[0]["body"]["input"], "second request")
            second_response = json.loads((second_artifact_dir / "response_body.json").read_text(encoding="utf-8"))
            self.assertEqual(second_response[0]["body"]["delta"], "second response")
            transcript = (second_artifact_dir / "websocket_transcript.txt").read_text(encoding="utf-8")
            self.assertIn("client", transcript)
            self.assertIn("server", transcript)
            self.assertNotIn("...<truncated preview>...", transcript)
            ui_log = (
                Path(tempdir)
                / "dataset"
                / "sessions"
                / "session-test"
                / "llm"
                / "ui.ndjson"
            )
            ui_log_text = ui_log.read_text(encoding="utf-8")
            self.assertEqual(ui_log_text.count("WEBSOCKET_TURN"), 2)
            self.assertIn("server_frames=1", ui_log_text)
            self.assertIn("2026-", ui_log_text)

    def test_websocket_message_skips_turn_without_request_marker(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir)
            handshake = self.fake_flow(addon, b"handshake")
            handshake.response.status_code = 101
            flow = self.fake_websocket_flow(
                handshake,
                [
                    types.SimpleNamespace(
                        from_client=True,
                        content='{"ordinary":"payload"}',
                        timestamp=1777906110.0,
                    ),
                    types.SimpleNamespace(
                        from_client=False,
                        content='{"type":"response.output_text.delta","delta":"ignored"}',
                        timestamp=1777906111.0,
                    ),
                ],
            )

            addon.websocket_message(flow)

            ui_log = (
                Path(tempdir)
                / "dataset"
                / "sessions"
                / "session-test"
                / "llm"
                / "ui.ndjson"
            )
            self.assertFalse(ui_log.exists())

    def test_websocket_message_honors_target_hosts(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            addon = self.load_addon(tempdir, target_hosts="capture.example.test")
            handshake = self.fake_flow(addon, b"handshake", host="skip.example.test")
            flow = self.fake_websocket_flow(
                handshake,
                [types.SimpleNamespace(from_client=False, content=b"ignored")],
            )

            with mock.patch.object(addon, "persist_websocket_flow") as persist_mock:
                addon.websocket_message(flow)

            persist_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
