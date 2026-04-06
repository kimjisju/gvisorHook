from __future__ import annotations

import argparse
import asyncio
import json
import logging
import signal
from collections import OrderedDict
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

from aiohttp import ClientSession, ClientTimeout, web

from .models import BrokerEnvelope, LLMExchange, SyscallEvent

LOG = logging.getLogger(__name__)


INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width,initial-scale=1" />
  <title>gVisor Syscall Approval</title>
  <style>
    :root{--bg:#f4efe6;--panel:rgba(255,255,255,.92);--ink:#1f2a30;--muted:#5d6c72;--accent:#0f766e;--deny:#b91c1c;--line:rgba(31,42,48,.12);--shadow:0 18px 50px rgba(31,42,48,.12);--warn:#f59e0b}
    *{box-sizing:border-box}body{margin:0;font-family:"IBM Plex Sans","Segoe UI",sans-serif;color:var(--ink);background:radial-gradient(circle at top left,rgba(15,118,110,.18),transparent 36%),radial-gradient(circle at top right,rgba(245,158,11,.16),transparent 28%),linear-gradient(180deg,#f7f3eb 0%,#efe7da 100%);min-height:100vh}
    header{padding:24px 28px 8px}h1{margin:0;font-size:1.8rem;letter-spacing:-.04em}.subtitle{color:var(--muted);margin-top:8px;max-width:880px;line-height:1.5}
    .banner{margin-top:14px;padding:14px 16px;border-radius:18px;background:rgba(15,118,110,.1);border:1px solid rgba(15,118,110,.18);font-size:.95rem;line-height:1.5}
    main{display:grid;grid-template-columns:minmax(280px,420px) minmax(380px,1fr);gap:18px;padding:16px 28px 28px}.panel{background:var(--panel);border:1px solid var(--line);border-radius:24px;box-shadow:var(--shadow);backdrop-filter:blur(8px)}
    .wide{grid-column:1/-1}.panel-header{display:flex;align-items:center;justify-content:space-between;padding:18px 20px 10px}.panel-title{font-weight:700;font-size:1rem}.panel-body{padding:0 18px 18px}.badge{font-size:.78rem;color:white;background:var(--accent);border-radius:999px;padding:6px 10px}
    .queue-list,.log-list,.llm-list{display:grid;gap:12px;max-height:calc(100vh - 220px);overflow:auto;padding-right:4px}.llm-list{max-height:620px}
    .event,.exchange{border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(255,255,255,.8)}.event.focused{outline:2px solid rgba(15,118,110,.24)}
    .event-head{display:flex;align-items:start;justify-content:space-between;gap:12px;margin-bottom:8px}.syscall,.exchange-kind{font-family:"IBM Plex Mono","Consolas",monospace;font-size:.85rem;color:var(--accent)}.summary,.exchange-summary{font-weight:650;line-height:1.45;word-break:break-word}
    .meta{margin-top:8px;color:var(--muted);font-size:.84rem;line-height:1.5;word-break:break-word}.actions{display:flex;gap:8px;margin-top:12px}
    button{border:0;border-radius:12px;padding:10px 12px;font:inherit;cursor:pointer;transition:transform .08s ease,opacity .12s ease}button:hover{transform:translateY(-1px)}button.allow{background:var(--accent);color:white}button.deny{background:var(--deny);color:white}button:disabled{opacity:.48;cursor:default;transform:none}
    .status{font-size:.78rem;border-radius:999px;padding:5px 9px;background:rgba(31,42,48,.08);color:var(--ink);white-space:nowrap}.status.allowed,.status.completed{background:rgba(15,118,110,.16);color:#0b5f59}.status.denied,.status.error{background:rgba(185,28,28,.16);color:#991b1b}.status.timeout,.status.pending{background:rgba(245,158,11,.18);color:#92400e}
    .empty{color:var(--muted);padding:14px;border:1px dashed var(--line);border-radius:16px}.connection{color:var(--muted);font-size:.88rem}.keycap{font-family:"IBM Plex Mono",monospace;border:1px solid var(--line);padding:2px 6px;border-radius:8px;background:rgba(255,255,255,.92);margin-left:4px}
    .payload{margin-top:10px;background:#f8fafb;border:1px solid var(--line);border-radius:14px;padding:12px;overflow:auto;max-height:320px;font-family:"IBM Plex Mono","Consolas",monospace;font-size:.78rem;line-height:1.5;white-space:pre-wrap;word-break:break-word}
    .payload-label{margin-top:10px;font-size:.78rem;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.06em}
    @media (max-width:1024px){main{grid-template-columns:1fr}.queue-list,.log-list,.llm-list{max-height:none}}
  </style>
</head>
<body>
  <header>
    <h1>gVisor Syscall Approval Console</h1>
    <div class="subtitle">Open Interpreter CLI stays in the terminal. This page shows hooked syscalls and the captured LLM request and response payloads flowing through the host-side mitmproxy tap.</div>
    <div class="banner"><strong>Web page:</strong> syscall approvals plus LLM traffic capture.<br><strong>Terminal:</strong> actual agent conversation and execution output.</div>
  </header>
  <main>
    <section class="panel">
      <div class="panel-header"><div class="panel-title">Pending approvals</div><div class="badge" id="pending-count">0 waiting</div></div>
      <div class="panel-body"><div class="connection" id="connection-state">Connecting...</div><div class="queue-list" id="pending-list"></div></div>
    </section>
    <section class="panel">
      <div class="panel-header"><div class="panel-title">Syscall log</div></div>
      <div class="panel-body"><div class="log-list" id="event-log"></div></div>
    </section>
    <section class="panel wide">
      <div class="panel-header"><div class="panel-title">LLM traffic</div><div class="connection">mitmproxy request and response capture</div></div>
      <div class="panel-body"><div class="llm-list" id="llm-log"></div></div>
    </section>
  </main>
  <script>
    const pendingList=document.getElementById("pending-list"); const eventLog=document.getElementById("event-log"); const llmLog=document.getElementById("llm-log"); const pendingCount=document.getElementById("pending-count"); const connectionState=document.getElementById("connection-state");
    const state={events:[],exchanges:[],focusedId:null};
    function sortEvents(events){return [...events].sort((a,b)=>new Date(b.started_at)-new Date(a.started_at));}
    function escapeHtml(v){return String(v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
    function prettyPayload(v){if(v===null||v===undefined)return ""; if(typeof v==="string") return v; try{return JSON.stringify(v,null,2);}catch(_err){return String(v);}}
    async function decide(id,decision){if(!id||!decision)return; await fetch(`/api/events/${id}/decision`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({decision})}); await refreshSnapshot();}
    function renderEvent(evt,actionable){
      const el=document.createElement("article"); el.className=`event ${evt.id===state.focusedId?"focused":""}`;
      const path=evt.path?`<div>path: ${escapeHtml(evt.path)}</div>`:""; const argv=evt.argv&&evt.argv.length?`<div>argv: ${escapeHtml(evt.argv.join(" "))}</div>`:""; const errno=evt.errno?`<div>errno: ${escapeHtml(evt.errno)}</div>`:"";
      el.innerHTML=`<div class="event-head"><div><div class="syscall">${escapeHtml(evt.syscall)}</div><div class="summary">${escapeHtml(evt.summary)}</div></div><div class="status ${evt.status}">${escapeHtml(evt.status)}</div></div><div class="meta"><div>container: ${escapeHtml(evt.container_id)} | pid/tid: ${evt.pid}/${evt.tid}</div>${path}${argv}${errno}<div>started: ${escapeHtml(evt.started_at)}</div></div>${actionable?`<div class="actions"><button class="allow" data-id="${evt.id}" data-decision="allow">Allow (y)</button><button class="deny" data-id="${evt.id}" data-decision="deny">Deny (n)</button></div>`:""}`;
      el.querySelectorAll("button").forEach((button)=>button.addEventListener("click",async()=>{await decide(button.dataset.id,button.dataset.decision);}));
      return el;
    }
    function renderExchange(exchange){
      const el=document.createElement("article"); el.className="exchange";
      const requestPayload=prettyPayload(exchange.request_body); const responsePayload=prettyPayload(exchange.response_body);
      const requestSection=requestPayload?`<div class="payload-label">Request Body</div><pre class="payload">${escapeHtml(requestPayload)}</pre>`:"";
      const responseSection=responsePayload?`<div class="payload-label">Response Body</div><pre class="payload">${escapeHtml(responsePayload)}</pre>`:"";
      const requestSummary=exchange.request_summary?`<div class="exchange-summary">${escapeHtml(exchange.request_summary)}</div>`:"";
      const responseSummary=exchange.response_summary?`<div class="meta"><strong>response:</strong> ${escapeHtml(exchange.response_summary)}</div>`:"";
      const model=exchange.model?`<div>model: ${escapeHtml(exchange.model)}</div>`:"";
      const responseStatus=exchange.response_status!==null&&exchange.response_status!==undefined?`<div>response_status: ${escapeHtml(exchange.response_status)}</div>`:"";
      const error=exchange.error?`<div>error: ${escapeHtml(exchange.error)}</div>`:"";
      el.innerHTML=`<div class="event-head"><div><div class="exchange-kind">${escapeHtml(exchange.method)} ${escapeHtml(exchange.url)}</div>${requestSummary}</div><div class="status ${exchange.status}">${escapeHtml(exchange.status)}</div></div><div class="meta">${model}${responseStatus}${error}<div>started: ${escapeHtml(exchange.started_at)}</div></div>${responseSummary}${requestSection}${responseSection}`;
      return el;
    }
    function render(){
      const events=sortEvents(state.events); const pending=events.filter((evt)=>evt.status==="pending"); const exchanges=sortEvents(state.exchanges);
      if(!state.focusedId||!pending.some((evt)=>evt.id===state.focusedId)){state.focusedId=pending[0]?.id??null;}
      pendingCount.textContent=`${pending.length} waiting`; pendingList.innerHTML=""; eventLog.innerHTML=""; llmLog.innerHTML="";
      if(!pending.length){pendingList.innerHTML='<div class="empty">No pending syscalls. The agent will pause here whenever a hooked operation happens.</div>';}
      for(const evt of pending){pendingList.appendChild(renderEvent(evt,true));}
      if(!events.length){eventLog.innerHTML='<div class="empty">No syscall events yet.</div>';}
      for(const evt of events){eventLog.appendChild(renderEvent(evt,false));}
      if(!exchanges.length){llmLog.innerHTML='<div class="empty">No LLM traffic captured yet.</div>';}
      for(const exchange of exchanges){llmLog.appendChild(renderExchange(exchange));}
    }
    function applyEnvelope(envelope){
      const payload=envelope.payload;
      if(envelope.type==="snapshot"){state.events=payload.events; state.exchanges=payload.llm_exchanges||[];}
      if(envelope.type==="event-upsert"){const idx=state.events.findIndex((evt)=>evt.id===payload.event.id); if(idx>=0) state.events[idx]=payload.event; else state.events.push(payload.event);}
      if(envelope.type==="llm-upsert"){const idx=state.exchanges.findIndex((evt)=>evt.id===payload.exchange.id); if(idx>=0) state.exchanges[idx]=payload.exchange; else state.exchanges.push(payload.exchange);}
      render();
    }
    async function refreshSnapshot(){
      try{
        const response = await fetch("/api/events", {cache:"no-store"});
        if(!response.ok) return;
        applyEnvelope(await response.json());
      }catch(_err){}
    }
    function connect(){
      const protocol=location.protocol==="https:"?"wss":"ws"; const ws=new WebSocket(`${protocol}://${location.host}/ws`);
      ws.onopen=()=>connectionState.textContent="Connected";
      ws.onclose=()=>{connectionState.textContent="Disconnected, retrying..."; setTimeout(connect,1000);};
      ws.onerror=()=>ws.close();
      ws.onmessage=(message)=>applyEnvelope(JSON.parse(message.data));
    }
    document.addEventListener("keydown",async(event)=>{if(!state.focusedId)return; if(event.key==="y") await decide(state.focusedId,"allow"); if(event.key==="n") await decide(state.focusedId,"deny");});
    setInterval(refreshSnapshot, 1000);
    refreshSnapshot();
    connect();
  </script>
</body>
</html>"""


class ApprovalBroker:
    def __init__(
        self,
        socket_path: Path,
        decision_timeout: float,
        *,
        tcp_host: str | None = None,
        tcp_port: int | None = None,
        event_log_path: Path | None = None,
        decision_dir: Path | None = None,
        llm_log_path: Path | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.decision_timeout = decision_timeout
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.event_log_path = event_log_path
        self.decision_dir = decision_dir
        self.llm_log_path = llm_log_path
        self._events: OrderedDict[str, SyscallEvent] = OrderedDict()
        self._llm_exchanges: OrderedDict[str, LLMExchange] = OrderedDict()
        self._pending: dict[str, asyncio.Future[str]] = {}
        self._websockets: set[web.WebSocketResponse] = set()
        self._ipc_server: asyncio.base_events.Server | None = None
        self._tcp_server: asyncio.base_events.Server | None = None
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()
        self._event_log_offset = 0
        self._event_log_buffer = ""
        self._llm_log_offset = 0
        self._llm_log_buffer = ""

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        self._ipc_server = await asyncio.start_unix_server(
            self._handle_ipc_client,
            path=str(self.socket_path),
        )
        self.socket_path.chmod(0o777)
        if self.tcp_host and self.tcp_port:
            self._tcp_server = await asyncio.start_server(
                self._handle_ipc_client,
                host=self.tcp_host,
                port=self.tcp_port,
            )
        if self.event_log_path is not None:
            self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
            self.event_log_path.touch(exist_ok=True)
        if self.decision_dir is not None:
            self.decision_dir.mkdir(parents=True, exist_ok=True)
        if self.llm_log_path is not None:
            self.llm_log_path.parent.mkdir(parents=True, exist_ok=True)
            self.llm_log_path.touch(exist_ok=True)
        if self.event_log_path is not None and self.decision_dir is not None:
            self._start_task(self._poll_event_log())
        if self.llm_log_path is not None:
            self._start_task(self._poll_llm_log())

    async def stop(self) -> None:
        for task in list(self._tasks):
            task.cancel()
        for task in list(self._tasks):
            with suppress(asyncio.CancelledError, Exception):
                await task
        if self._ipc_server is not None:
            self._ipc_server.close()
            await self._ipc_server.wait_closed()
        if self._tcp_server is not None:
            self._tcp_server.close()
            await self._tcp_server.wait_closed()
        with suppress(FileNotFoundError):
            self.socket_path.unlink()
        for ws in list(self._websockets):
            await ws.close()

    def _start_task(self, coro: Any) -> None:
        task = asyncio.create_task(coro)
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _handle_ipc_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            while True:
                raw = await reader.readline()
                if not raw:
                    return
                message = json.loads(raw.decode())
                msg_type = message.get("type")
                if msg_type == "heartbeat":
                    writer.write(b'{"type":"heartbeat"}\n')
                    await writer.drain()
                    continue
                if msg_type != "syscall_event":
                    writer.write(b'{"type":"decision_result","decision":"deny","errno":"EPERM"}\n')
                    await writer.drain()
                    continue
                event = SyscallEvent(**message["payload"])
                LOG.info(
                    "Received syscall event id=%s syscall=%s pid=%s path=%s",
                    event.id,
                    event.syscall,
                    event.pid,
                    event.path,
                )
                future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
                async with self._lock:
                    self._events[event.id] = event
                    self._pending[event.id] = future
                await self._broadcast(BrokerEnvelope("event-upsert", {"event": event.to_dict()}).to_dict())
                decision = "deny"
                errno = "EPERM"
                try:
                    decision = await asyncio.wait_for(future, timeout=self.decision_timeout)
                    errno = None if decision == "allow" else "EPERM"
                except asyncio.TimeoutError:
                    LOG.warning("Timed out waiting for decision id=%s syscall=%s", event.id, event.syscall)
                    await self._set_status(event.id, "timeout", errno)
                else:
                    LOG.info("Decision id=%s syscall=%s decision=%s", event.id, event.syscall, decision)
                    await self._set_status(event.id, "allowed" if decision == "allow" else "denied", errno)
                writer.write(
                    json.dumps(
                        {"type": "decision_result", "id": event.id, "decision": decision, "errno": errno}
                    ).encode()
                    + b"\n"
                )
                await writer.drain()
        except Exception as exc:  # pragma: no cover
            LOG.exception("IPC handler failed: %s", exc)
        finally:
            writer.close()
            with suppress(Exception):
                await writer.wait_closed()

    async def _poll_event_log(self) -> None:
        assert self.event_log_path is not None
        while True:
            try:
                if self.event_log_path.exists():
                    with self.event_log_path.open("r", encoding="utf-8") as fh:
                        fh.seek(self._event_log_offset)
                        chunk = fh.read()
                        self._event_log_offset = fh.tell()
                    if chunk:
                        self._event_log_buffer += chunk
                        while "\n" in self._event_log_buffer:
                            line, self._event_log_buffer = self._event_log_buffer.split("\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            payload = json.loads(line)
                            event = SyscallEvent(**payload)
                            await self._register_file_event(event)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.exception("Event log polling failed: %s", exc)
            await asyncio.sleep(0.2)

    async def _poll_llm_log(self) -> None:
        assert self.llm_log_path is not None
        while True:
            try:
                if self.llm_log_path.exists():
                    with self.llm_log_path.open("r", encoding="utf-8") as fh:
                        fh.seek(self._llm_log_offset)
                        chunk = fh.read()
                        self._llm_log_offset = fh.tell()
                    if chunk:
                        self._llm_log_buffer += chunk
                        while "\n" in self._llm_log_buffer:
                            line, self._llm_log_buffer = self._llm_log_buffer.split("\n", 1)
                            line = line.strip()
                            if not line:
                                continue
                            payload = json.loads(line)
                            if payload.get("type") != "llm-upsert":
                                continue
                            exchange = LLMExchange(**payload["payload"])
                            await self._upsert_llm_exchange(exchange)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                LOG.exception("LLM log polling failed: %s", exc)
            await asyncio.sleep(0.2)

    async def _register_file_event(self, event: SyscallEvent) -> None:
        async with self._lock:
            if event.id in self._events:
                return
            self._events[event.id] = event
            future = asyncio.get_running_loop().create_future()
            self._pending[event.id] = future
        LOG.info(
            "Received syscall event id=%s syscall=%s pid=%s path=%s (file backend)",
            event.id,
            event.syscall,
            event.pid,
            event.path,
        )
        await self._broadcast(BrokerEnvelope("event-upsert", {"event": event.to_dict()}).to_dict())
        self._start_task(self._await_file_decision(event.id, event.syscall, future))

    async def _upsert_llm_exchange(self, exchange: LLMExchange) -> None:
        async with self._lock:
            self._llm_exchanges[exchange.id] = exchange
            payload = exchange.to_dict()
        await self._broadcast(BrokerEnvelope("llm-upsert", {"exchange": payload}).to_dict())

    async def _await_file_decision(
        self,
        event_id: str,
        syscall: str,
        future: asyncio.Future[str],
    ) -> None:
        decision = "deny"
        errno = "EPERM"
        status = "timeout"
        try:
            decision = await asyncio.wait_for(future, timeout=self.decision_timeout)
            errno = None if decision == "allow" else "EPERM"
            status = "allowed" if decision == "allow" else "denied"
        except asyncio.TimeoutError:
            LOG.warning("Timed out waiting for decision id=%s syscall=%s", event_id, syscall)
        except asyncio.CancelledError:
            raise
        await self._write_decision_file(event_id, decision, errno)
        await self._set_status(event_id, status, errno)

    async def _write_decision_file(self, event_id: str, decision: str, errno: str | None) -> None:
        if self.decision_dir is None:
            return
        payload = {
            "type": "decision_result",
            "id": event_id,
            "decision": decision,
            "errno": errno,
        }
        decision_path = self.decision_dir / f"{event_id}.json"
        decision_path.write_text(json.dumps(payload), encoding="utf-8")

    async def _set_status(self, event_id: str, status: str, errno: str | None) -> None:
        async with self._lock:
            event = self._events.get(event_id)
            if event is None:
                return
            self._events[event_id] = replace(event, status=status, errno=errno)
            self._pending.pop(event_id, None)
            updated = self._events[event_id]
        await self._broadcast(BrokerEnvelope("event-upsert", {"event": updated.to_dict()}).to_dict())

    async def decide(self, event_id: str, decision: str) -> bool:
        async with self._lock:
            future = self._pending.get(event_id)
            if future is None or future.done():
                return False
            future.set_result(decision)
            return True

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            events = [event.to_dict() for event in self._events.values()]
            llm_exchanges = [exchange.to_dict() for exchange in self._llm_exchanges.values()]
        return BrokerEnvelope("snapshot", {"events": events, "llm_exchanges": llm_exchanges}).to_dict()

    async def _broadcast(self, message: dict[str, Any]) -> None:
        stale: list[web.WebSocketResponse] = []
        for ws in self._websockets:
            try:
                await ws.send_json(message)
            except Exception:
                stale.append(ws)
        for ws in stale:
            self._websockets.discard(ws)


def _install_routes(app: web.Application) -> None:
    broker: ApprovalBroker = app["broker"]

    async def index(_: web.Request) -> web.Response:
        return web.Response(text=INDEX_HTML, content_type="text/html")

    async def health(_: web.Request) -> web.Response:
        return web.json_response({"ok": True})

    async def events_handler(_: web.Request) -> web.Response:
        return web.json_response(await broker.snapshot())

    async def websocket_handler(request: web.Request) -> web.WebSocketResponse:
        ws = web.WebSocketResponse(heartbeat=20)
        await ws.prepare(request)
        broker._websockets.add(ws)
        await ws.send_json(await broker.snapshot())
        try:
            async for _ in ws:
                pass
        finally:
            broker._websockets.discard(ws)
        return ws

    async def decide_handler(request: web.Request) -> web.Response:
        event_id = request.match_info["event_id"]
        payload = await request.json()
        decision = payload.get("decision")
        if decision not in {"allow", "deny"}:
            raise web.HTTPBadRequest(text="decision must be allow or deny")
        updated = await broker.decide(event_id, decision)
        if not updated:
            raise web.HTTPNotFound(text=f"pending event {event_id} not found")
        return web.json_response({"ok": True})

    async def openai_proxy(request: web.Request) -> web.StreamResponse:
        tail = request.match_info.get("tail", "")
        target = f"https://api.openai.com/{tail}"
        if request.query_string:
            target = f"{target}?{request.query_string}"

        excluded = {"host", "content-length"}
        headers = {
            key: value
            for key, value in request.headers.items()
            if key.lower() not in excluded
        }
        body = await request.read()
        client: ClientSession = app["http_client"]
        request_kwargs: dict[str, Any] = {
            "method": request.method,
            "url": target,
            "headers": headers,
            "data": body if body else None,
            "allow_redirects": False,
        }
        llm_proxy_url = app["llm_proxy_url"]
        if llm_proxy_url:
            request_kwargs["proxy"] = llm_proxy_url
            request_kwargs["ssl"] = False
        upstream = await client.request(**request_kwargs)
        response = web.StreamResponse(status=upstream.status, reason=upstream.reason)
        for key, value in upstream.headers.items():
            if key.lower() not in {"content-length", "transfer-encoding", "content-encoding", "connection"}:
                response.headers[key] = value
        await response.prepare(request)
        async for chunk in upstream.content.iter_chunked(65536):
            await response.write(chunk)
        await response.write_eof()
        await upstream.release()
        return response

    app.router.add_get("/", index)
    app.router.add_get("/api/health", health)
    app.router.add_get("/api/events", events_handler)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_post("/api/events/{event_id}/decision", decide_handler)
    app.router.add_route("*", "/openai/{tail:.*}", openai_proxy)


async def create_app(
    socket_path: Path,
    decision_timeout: float,
    *,
    tcp_host: str | None = None,
    tcp_port: int | None = None,
    event_log_path: Path | None = None,
    decision_dir: Path | None = None,
    llm_log_path: Path | None = None,
    llm_proxy_url: str | None = None,
) -> web.Application:
    broker = ApprovalBroker(
        socket_path=socket_path,
        decision_timeout=decision_timeout,
        tcp_host=tcp_host,
        tcp_port=tcp_port,
        event_log_path=event_log_path,
        decision_dir=decision_dir,
        llm_log_path=llm_log_path,
    )
    await broker.start()
    app = web.Application()
    app["broker"] = broker
    app["llm_proxy_url"] = llm_proxy_url
    app["http_client"] = ClientSession(timeout=ClientTimeout(total=None))

    async def on_cleanup(_: web.Application) -> None:
        await broker.stop()
        await app["http_client"].close()

    app.on_cleanup.append(on_cleanup)
    _install_routes(app)
    return app


async def serve(args: argparse.Namespace) -> None:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s %(name)s: %(message)s")
    app = await create_app(
        socket_path=Path(args.socket_path),
        decision_timeout=args.decision_timeout,
        tcp_host=args.tcp_host,
        tcp_port=args.tcp_port,
        event_log_path=Path(args.event_log_path) if args.event_log_path else None,
        decision_dir=Path(args.decision_dir) if args.decision_dir else None,
        llm_log_path=Path(args.llm_log_path) if args.llm_log_path else None,
        llm_proxy_url=args.llm_proxy_url,
    )
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    hosts = ["127.0.0.1"]
    if args.bind_host and args.bind_host not in hosts:
        hosts.append(args.bind_host)
    sites = [web.TCPSite(runner, host=host, port=args.web_port) for host in hosts]
    for site in sites:
        await site.start()
    if args.http_socket_path:
        http_socket_path = Path(args.http_socket_path)
        if http_socket_path.exists():
            http_socket_path.unlink()
        unix_site = web.UnixSite(runner, path=str(http_socket_path))
        await unix_site.start()
        http_socket_path.chmod(0o777)
    approval_endpoints: list[str] = []
    if args.event_log_path and args.decision_dir:
        approval_endpoints.append(f"file://{args.event_log_path} -> {args.decision_dir}")
    if args.tcp_host and args.tcp_port:
        approval_endpoints.append(f"tcp://{args.tcp_host}:{args.tcp_port}")
    approval_endpoints.append(f"unix://{args.socket_path}")
    mitm_text = args.llm_proxy_url if args.llm_proxy_url else "disabled"
    LOG.info(
        "Broker ready on %s; approval IPC on %s; llm mitm on %s",
        ", ".join(f"http://{host}:{args.web_port}" for host in hosts),
        ", ".join(approval_endpoints),
        mitm_text,
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signame in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(signame, stop_event.set)
    await stop_event.wait()
    await runner.cleanup()
