from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from gvisor_hook.broker import ApprovalBroker


class ApprovalBrokerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.socket_path = Path(self.tempdir.name) / "broker.sock"
        self.event_log_path = Path(self.tempdir.name) / "events.ndjson"
        self.decision_dir = Path(self.tempdir.name) / "decisions"
        self.broker = ApprovalBroker(
            self.socket_path,
            decision_timeout=0.2,
            event_log_path=self.event_log_path,
            decision_dir=self.decision_dir,
        )
        await self.broker.start()

    async def asyncTearDown(self) -> None:
        await self.broker.stop()
        self.tempdir.cleanup()

    async def test_allow_decision_round_trip(self) -> None:
        payload = {
            "id": "evt-1",
            "container_id": "demo",
            "pid": 10,
            "tid": 11,
            "syscall": "openat",
            "summary": "open write-intent",
            "path": "/tmp/demo.txt",
            "argv": None,
            "started_at": "2026-04-04T00:00:00Z",
            "status": "pending",
        }

        async def responder() -> None:
            await asyncio.sleep(0.05)
            self.assertTrue(await self.broker.decide("evt-1", "allow"))

        task = asyncio.create_task(responder())
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        writer.write(json.dumps({"type": "syscall_event", "payload": payload}).encode() + b"\n")
        await writer.drain()
        response = json.loads((await reader.readline()).decode())
        self.assertEqual(response["decision"], "allow")
        await task
        writer.close()
        await writer.wait_closed()

    async def test_timeout_denies(self) -> None:
        payload = {
            "id": "evt-2",
            "container_id": "demo",
            "pid": 10,
            "tid": 11,
            "syscall": "execve",
            "summary": "execve /bin/ls",
            "path": "/bin/ls",
            "argv": ["/bin/ls"],
            "started_at": "2026-04-04T00:00:00Z",
            "status": "pending",
        }
        reader, writer = await asyncio.open_unix_connection(str(self.socket_path))
        writer.write(json.dumps({"type": "syscall_event", "payload": payload}).encode() + b"\n")
        await writer.drain()
        response = json.loads((await reader.readline()).decode())
        self.assertEqual(response["decision"], "deny")
        self.assertEqual(response["errno"], "EPERM")
        writer.close()
        await writer.wait_closed()

    async def test_file_backend_round_trip(self) -> None:
        payload = {
            "id": "evt-file-1",
            "container_id": "demo",
            "pid": 10,
            "tid": 11,
            "syscall": "write",
            "summary": "write 10 bytes",
            "path": "/tmp/workspace/demo.txt",
            "argv": None,
            "started_at": "2026-04-04T00:00:00Z",
            "status": "pending",
        }
        self.event_log_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")
        await asyncio.sleep(0.3)
        snapshot = await self.broker.snapshot()
        self.assertEqual(len(snapshot["payload"]["events"]), 1)
        self.assertTrue(await self.broker.decide("evt-file-1", "allow"))
        await asyncio.sleep(0.3)
        decision_path = self.decision_dir / "evt-file-1.json"
        self.assertTrue(decision_path.exists())
        decision = json.loads(decision_path.read_text(encoding="utf-8"))
        self.assertEqual(decision["decision"], "allow")
