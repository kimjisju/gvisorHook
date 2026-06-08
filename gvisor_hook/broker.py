from __future__ import annotations

import argparse
import asyncio
import json
import logging
import re
import signal
import time
from collections import OrderedDict
from contextlib import suppress
from dataclasses import replace
from pathlib import Path
from typing import Any

from aiohttp import web

from .models import BrokerEnvelope, LLMExchange, SyscallEvent
from .reason_pipeline import ReasonPipelineConfig, run_reason_pipeline_event

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
    .wide{grid-column:1/-1}.panel-header{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:18px 20px 10px}.panel-title{font-weight:700;font-size:1rem}.panel-actions{display:flex;align-items:center;gap:10px}.panel-body{padding:0 18px 18px}.badge{font-size:.78rem;color:white;background:var(--accent);border-radius:999px;padding:6px 10px}
    .toggle{display:inline-flex;align-items:center;gap:7px;border:1px solid var(--line);border-radius:999px;padding:5px 9px;background:rgba(255,255,255,.72);color:var(--muted);font-size:.82rem;font-weight:650;cursor:pointer}.toggle input{accent-color:var(--accent)}
    .queue-list,.log-list,.llm-list{display:grid;gap:12px;max-height:calc(100vh - 220px);overflow:auto;padding-right:4px}.llm-list{max-height:620px}
    .event,.exchange{border:1px solid var(--line);border-radius:18px;padding:14px;background:rgba(255,255,255,.8)}.event.focused{outline:2px solid rgba(15,118,110,.24)}
    .event-head{display:flex;align-items:start;justify-content:space-between;gap:12px;margin-bottom:8px}.syscall,.exchange-kind{font-family:"IBM Plex Mono","Consolas",monospace;font-size:.85rem;color:var(--accent)}.summary,.exchange-summary{font-weight:650;line-height:1.45;word-break:break-word}
    .meta{margin-top:8px;color:var(--muted);font-size:.84rem;line-height:1.5;word-break:break-word}.actions{display:flex;gap:8px;margin-top:12px}
    button{border:0;border-radius:12px;padding:10px 12px;font:inherit;cursor:pointer;transition:transform .08s ease,opacity .12s ease}button:hover{transform:translateY(-1px)}button.allow{background:var(--accent);color:white}button.deny{background:var(--deny);color:white}button:disabled{opacity:.48;cursor:default;transform:none}
    .status{font-size:.78rem;border-radius:999px;padding:5px 9px;background:rgba(31,42,48,.08);color:var(--ink);white-space:nowrap}.status.allowed,.status.completed{background:rgba(15,118,110,.16);color:#0b5f59}.status.denied,.status.error{background:rgba(185,28,28,.16);color:#991b1b}.status.timeout,.status.pending{background:rgba(245,158,11,.18);color:#92400e}.status.guard_checking{background:rgba(59,130,246,.16);color:#1d4ed8}
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
      <div class="panel-header"><div class="panel-title">Pending approvals</div><div class="panel-actions"><label class="toggle" title="Automatically allow pending and future syscalls"><input type="checkbox" id="auto-accept-toggle" /> <span>AutoAccept</span></label><div class="badge" id="pending-count">0 waiting</div></div></div>
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
    const pendingList=document.getElementById("pending-list"); const eventLog=document.getElementById("event-log"); const llmLog=document.getElementById("llm-log"); const pendingCount=document.getElementById("pending-count"); const connectionState=document.getElementById("connection-state"); const autoAcceptToggle=document.getElementById("auto-accept-toggle");
    const state={events:[],exchanges:[],focusedId:null,wsConnected:false,autoAccept:false};
    function sortEvents(events){return [...events].sort((a,b)=>new Date(b.started_at)-new Date(a.started_at));}
    function escapeHtml(v){return String(v).replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;");}
    function prettyPayload(v){if(v===null||v===undefined)return ""; if(typeof v==="string") return v; try{return JSON.stringify(v,null,2);}catch(_err){return String(v);}}
    function escapeSelector(v){if(window.CSS&&typeof window.CSS.escape==="function") return window.CSS.escape(v); return String(v).replaceAll("\\\\","\\\\\\\\").replaceAll('"','\\\\"');}
    function captureScrollState(container){
      const maxScroll=Math.max(0,container.scrollHeight-container.clientHeight);
      const payloadScrolls=Array.from(container.querySelectorAll("[data-scroll-key]")).map((node)=>({key:node.dataset.scrollKey,top:node.scrollTop,left:node.scrollLeft}));
      if(container.scrollTop<=8){return {mode:"top",payloadScrolls};}
      if(maxScroll-container.scrollTop<=8){return {mode:"bottom",payloadScrolls};}
      const anchor=Array.from(container.children).find((node)=>node.dataset.anchorId&&(node.offsetTop+node.offsetHeight)>container.scrollTop);
      if(anchor){return {mode:"anchor",anchorId:anchor.dataset.anchorId,offset:anchor.offsetTop-container.scrollTop,payloadScrolls};}
      return {mode:"offset",top:container.scrollTop,left:container.scrollLeft,payloadScrolls};
    }
    function restoreScrollState(container,snapshot){
      if(!snapshot) return;
      if(snapshot.mode==="top"){container.scrollTop=0;}
      else if(snapshot.mode==="bottom"){container.scrollTop=Math.max(0,container.scrollHeight-container.clientHeight);}
      else if(snapshot.mode==="anchor"&&snapshot.anchorId){
        const anchor=container.querySelector(`[data-anchor-id="${escapeSelector(snapshot.anchorId)}"]`);
        if(anchor){container.scrollTop=Math.max(0,anchor.offsetTop-snapshot.offset);}
        else if(Number.isFinite(snapshot.top)){container.scrollTop=snapshot.top;}
      }else if(Number.isFinite(snapshot.top)){container.scrollTop=snapshot.top; if(Number.isFinite(snapshot.left)) container.scrollLeft=snapshot.left;}
      for(const payloadState of snapshot.payloadScrolls||[]){
        const payload=container.querySelector(`[data-scroll-key="${escapeSelector(payloadState.key)}"]`);
        if(payload){payload.scrollTop=payloadState.top||0; payload.scrollLeft=payloadState.left||0;}
      }
    }
    async function decide(id,decision){if(!id||!decision)return; await fetch(`/api/events/${id}/decision`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({decision})}); if(!state.wsConnected) await refreshSnapshot();}
    async function setAutoAccept(enabled){autoAcceptToggle.disabled=true; try{const response=await fetch("/api/auto-accept",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({enabled})}); if(response.ok){state.autoAccept=enabled;} if(!state.wsConnected) await refreshSnapshot();}finally{autoAcceptToggle.disabled=false; renderControls();}}
    function renderControls(){autoAcceptToggle.checked=!!state.autoAccept;}
    function renderEvent(evt,actionable){
      const el=document.createElement("article"); el.className=`event ${evt.id===state.focusedId?"focused":""}`;
      el.dataset.anchorId=`event:${evt.id}`;
      const path=evt.path?`<div>path: ${escapeHtml(evt.path)}</div>`:""; const argv=evt.argv&&evt.argv.length?`<div>argv: ${escapeHtml(evt.argv.join(" "))}</div>`:""; const errno=evt.errno?`<div>errno: ${escapeHtml(evt.errno)}</div>`:"";
      el.innerHTML=`<div class="event-head"><div><div class="syscall">${escapeHtml(evt.syscall)}</div><div class="summary">${escapeHtml(evt.summary)}</div></div><div class="status ${evt.status}">${escapeHtml(evt.status)}</div></div><div class="meta"><div>container: ${escapeHtml(evt.container_id)} | pid/tid: ${evt.pid}/${evt.tid}</div>${path}${argv}${errno}<div>started: ${escapeHtml(evt.started_at)}</div></div>${actionable?`<div class="actions"><button class="allow" data-id="${evt.id}" data-decision="allow">Allow (y)</button><button class="deny" data-id="${evt.id}" data-decision="deny">Deny (n)</button></div>`:""}`;
      el.querySelectorAll("button").forEach((button)=>button.addEventListener("click",async()=>{await decide(button.dataset.id,button.dataset.decision);}));
      return el;
    }
    function renderExchange(exchange){
      const el=document.createElement("article"); el.className="exchange";
      el.dataset.anchorId=`exchange:${exchange.id}`;
      const requestPayload=prettyPayload(exchange.request_body); const responsePayload=prettyPayload(exchange.response_body);
      const requestSection=requestPayload?`<div class="payload-label">Request Body</div><pre class="payload" data-scroll-key="request:${escapeHtml(exchange.id)}">${escapeHtml(requestPayload)}</pre>`:"";
      const responseSection=responsePayload?`<div class="payload-label">Response Body</div><pre class="payload" data-scroll-key="response:${escapeHtml(exchange.id)}">${escapeHtml(responsePayload)}</pre>`:"";
      const requestSummary=exchange.request_summary?`<div class="exchange-summary">${escapeHtml(exchange.request_summary)}</div>`:"";
      const responseSummary=exchange.response_summary?`<div class="meta"><strong>response:</strong> ${escapeHtml(exchange.response_summary)}</div>`:"";
      const model=exchange.model?`<div>model: ${escapeHtml(exchange.model)}</div>`:"";
      const responseStatus=exchange.response_status!==null&&exchange.response_status!==undefined?`<div>response_status: ${escapeHtml(exchange.response_status)}</div>`:"";
      const sessionId=exchange.session_id?`<div>session_id: ${escapeHtml(exchange.session_id)}</div>`:"";
      const requestBytes=exchange.request_body_bytes!==null&&exchange.request_body_bytes!==undefined?`<div>request_bytes: ${escapeHtml(exchange.request_body_bytes)}</div>`:"";
      const responseBytes=exchange.response_body_bytes!==null&&exchange.response_body_bytes!==undefined?`<div>response_bytes: ${escapeHtml(exchange.response_body_bytes)}</div>`:"";
      const requestHeadersPath=exchange.request_headers_path?`<div>request_headers_path: ${escapeHtml(exchange.request_headers_path)}</div>`:"";
      const requestPath=exchange.request_body_path?`<div>request_body_path: ${escapeHtml(exchange.request_body_path)}</div>`:"";
      const responseHeadersPath=exchange.response_headers_path?`<div>response_headers_path: ${escapeHtml(exchange.response_headers_path)}</div>`:"";
      const responsePath=exchange.response_body_path?`<div>response_body_path: ${escapeHtml(exchange.response_body_path)}</div>`:"";
      const metaPath=exchange.meta_path?`<div>meta_path: ${escapeHtml(exchange.meta_path)}</div>`:"";
      const stream=exchange.is_stream?`<div>stream: true</div>`:"";
      const error=exchange.error?`<div>error: ${escapeHtml(exchange.error)}</div>`:"";
      el.innerHTML=`<div class="event-head"><div><div class="exchange-kind">${escapeHtml(exchange.method)} ${escapeHtml(exchange.url)}</div>${requestSummary}</div><div class="status ${exchange.status}">${escapeHtml(exchange.status)}</div></div><div class="meta">${model}${sessionId}${responseStatus}${requestBytes}${responseBytes}${stream}${requestHeadersPath}${requestPath}${responseHeadersPath}${responsePath}${metaPath}${error}<div>started: ${escapeHtml(exchange.started_at)}</div></div>${responseSummary}${requestSection}${responseSection}`;
      return el;
    }
    function renderSyscalls(){
      const events=sortEvents(state.events); const pending=events.filter((evt)=>evt.status==="pending");
      if(!state.focusedId||!pending.some((evt)=>evt.id===state.focusedId)){state.focusedId=pending[0]?.id??null;}
      const pendingScroll=captureScrollState(pendingList); const eventScroll=captureScrollState(eventLog);
      pendingCount.textContent=`${pending.length} waiting`; pendingList.innerHTML=""; eventLog.innerHTML="";
      if(!pending.length){pendingList.innerHTML='<div class="empty">No pending syscalls. The agent will pause here whenever a hooked operation happens.</div>';}
      for(const evt of pending){pendingList.appendChild(renderEvent(evt,true));}
      if(!events.length){eventLog.innerHTML='<div class="empty">No syscall events yet.</div>';}
      for(const evt of events){eventLog.appendChild(renderEvent(evt,false));}
      restoreScrollState(pendingList,pendingScroll); restoreScrollState(eventLog,eventScroll);
    }
    function renderLLM(){
      const exchanges=sortEvents(state.exchanges);
      const llmScroll=captureScrollState(llmLog);
      llmLog.innerHTML="";
      if(!exchanges.length){llmLog.innerHTML='<div class="empty">No LLM traffic captured yet.</div>';}
      for(const exchange of exchanges){llmLog.appendChild(renderExchange(exchange));}
      restoreScrollState(llmLog,llmScroll);
    }
    function renderAll(){
      renderControls();
      renderSyscalls();
      renderLLM();
    }
    function applyEnvelope(envelope){
      const payload=envelope.payload;
      if(envelope.type==="snapshot"){state.events=payload.events; state.exchanges=payload.llm_exchanges||[]; state.autoAccept=!!payload.auto_accept; renderAll(); return;}
      if(envelope.type==="event-upsert"){const idx=state.events.findIndex((evt)=>evt.id===payload.event.id); if(idx>=0) state.events[idx]=payload.event; else state.events.push(payload.event); renderSyscalls(); return;}
      if(envelope.type==="llm-upsert"){const idx=state.exchanges.findIndex((evt)=>evt.id===payload.exchange.id); if(idx>=0) state.exchanges[idx]=payload.exchange; else state.exchanges.push(payload.exchange); renderLLM();}
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
      ws.onopen=()=>{state.wsConnected=true; connectionState.textContent="Connected";};
      ws.onclose=()=>{state.wsConnected=false; connectionState.textContent="Disconnected, retrying..."; setTimeout(connect,1000);};
      ws.onerror=()=>ws.close();
      ws.onmessage=(message)=>applyEnvelope(JSON.parse(message.data));
    }
    autoAcceptToggle.addEventListener("change",async()=>{await setAutoAccept(autoAcceptToggle.checked);});
    document.addEventListener("keydown",async(event)=>{if(!state.focusedId)return; if(event.key==="y") await decide(state.focusedId,"allow"); if(event.key==="n") await decide(state.focusedId,"deny");});
    setInterval(()=>{if(!state.wsConnected) refreshSnapshot();}, 1000);
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
        reason_pipeline_config: ReasonPipelineConfig | None = None,
    ) -> None:
        self.socket_path = socket_path
        self.decision_timeout = decision_timeout
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        self.event_log_path = event_log_path
        self.decision_dir = decision_dir
        self.llm_log_path = llm_log_path
        self.reason_pipeline_config = reason_pipeline_config
        self._events: OrderedDict[str, SyscallEvent] = OrderedDict()
        self._llm_exchanges: OrderedDict[str, LLMExchange] = OrderedDict()
        self._pending: dict[str, asyncio.Future[str]] = {}
        self._websockets: set[web.WebSocketResponse] = set()
        self._auto_accept = False
        self._ipc_server: asyncio.base_events.Server | None = None
        self._tcp_server: asyncio.base_events.Server | None = None
        self._lock = asyncio.Lock()
        self._tasks: set[asyncio.Task[None]] = set()
        self._approval_grants: list[dict[str, Any]] = []
        self._event_log_offset = 0
        self._event_log_buffer = ""
        self._llm_log_offset = 0
        self._llm_log_buffer = ""
        self._reason_pipeline_semaphore = (
            asyncio.Semaphore(reason_pipeline_config.max_concurrency) if reason_pipeline_config is not None else None
        )

    def _extract_workspace_paths(self, event: SyscallEvent) -> set[str]:
        text_parts = [event.summary or "", event.path or ""]
        if event.argv:
            text_parts.extend(str(item) for item in event.argv)
        text = " ".join(text_parts)
        paths = set(re.findall(r"/tmp/workspace/[^\s'\";&|<>]+", text))
        action = self._approval_action(event)
        if action == "permission_change":
            paths.update(re.findall(r"(?:chmod|chown)\s+(?:-[A-Za-z0-9]+\s+)?\S+\s+([^\s'\";&|<>]+)", text))
        elif action == "file_delete":
            paths.update(re.findall(r"(?:rm|rmdir|unlink)\s+(?:-[A-Za-z0-9]+\s+)?([^\s'\";&|<>]+)", text))
        if event.path and event.path != "[unknown]":
            paths.add(event.path)
        normalized = set()
        for path in paths:
            cleaned = path.strip()
            if not cleaned:
                continue
            normalized.add(cleaned)
            if not cleaned.startswith("/"):
                normalized.add(f"/tmp/workspace/{cleaned.lstrip('./')}")
        paths = normalized
        return paths

    def _approval_action(self, event: SyscallEvent) -> str | None:
        text_parts = [event.syscall or "", event.summary or "", event.path or ""]
        if event.argv:
            text_parts.extend(str(item) for item in event.argv)
        text = " ".join(text_parts).lower()
        syscall = (event.syscall or "").lower()
        if syscall in {"chmod", "fchmod", "fchmodat", "chown", "fchown", "fchownat", "lchown"}:
            return "permission_change"
        if re.search(r"(^|[\s'\";&|])(?:/usr/bin/|/bin/)?(?:chmod|chown)\b", text):
            return "permission_change"
        if syscall in {"unlink", "unlinkat", "rmdir"}:
            return "file_delete"
        if re.search(r"(^|[\s'\";&|])(?:/usr/bin/|/bin/)?(?:rm|rmdir|unlink)\b", text):
            return "file_delete"
        return None

    def _remember_user_allow(self, event: SyscallEvent) -> None:
        action = self._approval_action(event)
        paths = self._extract_workspace_paths(event)
        if action is None or not paths:
            return
        self._approval_grants.append(
            {
                "container_id": event.container_id,
                "action": action,
                "paths": paths,
                "expires_at": time.monotonic() + 20.0,
            }
        )
        self._approval_grants = self._approval_grants[-64:]

    def _has_user_allow_grant(self, event: SyscallEvent) -> bool:
        action = self._approval_action(event)
        paths = self._extract_workspace_paths(event)
        if action is None or not paths:
            return False
        now = time.monotonic()
        self._approval_grants = [
            grant for grant in self._approval_grants if grant.get("expires_at", 0) > now
        ]
        for grant in self._approval_grants:
            if grant.get("container_id") != event.container_id:
                continue
            if grant.get("action") != action:
                continue
            if paths & set(grant.get("paths", set())):
                return True
        return False

    async def start(self) -> None:
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        if self.socket_path.exists():
            self.socket_path.unlink()
        try:
            self._ipc_server = await asyncio.start_unix_server(
                self._handle_ipc_client,
                path=str(self.socket_path),
            )
            self.socket_path.chmod(0o777)
        except PermissionError as exc:
            # Some restricted environments disallow AF_UNIX sockets. Allow the broker
            # to operate in TCP-only mode when configured.
            LOG.warning("Unix IPC disabled (permission error): %s", exc)
            self._ipc_server = None
        if self.tcp_host and self.tcp_port:
            self._tcp_server = await asyncio.start_server(
                self._handle_ipc_client,
                host=self.tcp_host,
                port=self.tcp_port,
            )
            sockets = getattr(self._tcp_server, "sockets", None)
            if sockets:
                with suppress(Exception):
                    self.tcp_port = int(sockets[0].getsockname()[1])
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
        if self._ipc_server is None and self._tcp_server is None:
            raise RuntimeError("broker has no usable IPC backend (unix and tcp both unavailable)")

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

    def _latest_llm_exchange(self) -> LLMExchange | None:
        for exchange in reversed(self._llm_exchanges.values()):
            if exchange.status == "completed":
                return exchange
        return None

    def _start_reason_pipeline(self, event: SyscallEvent) -> None:
        if self.reason_pipeline_config is None:
            return
        self._start_task(self._run_reason_pipeline(event))

    async def _run_reason_pipeline(self, event: SyscallEvent) -> dict[str, Any] | None:
        assert self.reason_pipeline_config is not None
        exchange = self._latest_llm_exchange()
        try:
            if self._reason_pipeline_semaphore is None:
                return await run_reason_pipeline_event(
                    self.reason_pipeline_config,
                    exchange=exchange,
                    syscall_event=event,
                )
            async with self._reason_pipeline_semaphore:
                return await run_reason_pipeline_event(
                    self.reason_pipeline_config,
                    exchange=exchange,
                    syscall_event=event,
                )
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            LOG.exception("Reason pipeline failed for event id=%s: %s", event.id, exc)
            return None

    async def _guard_decision_for_event(self, event: SyscallEvent) -> tuple[str, str]:
        if self.reason_pipeline_config is None:
            return "USER_CONFIRM", "Reason pipeline is not configured."

        record = await self._run_reason_pipeline(event)
        if not record:
            return "USER_CONFIRM", "Reason pipeline failed before producing a Guard LLM result."

        payload = record.get("payload", {})
        guard_decision = payload.get("guard_decision") or {}
        decision = str(guard_decision.get("decision", "USER_CONFIRM")).upper()
        if decision == "ALLOW":
            return "ALLOW", "Guard LLM allowed the syscall."
        if decision == "USER_CONFIRM":
            reason = ""
            intents = guard_decision.get("intents") or []
            if intents:
                reason = str(intents[0].get("reason", ""))
            return "USER_CONFIRM", reason or "Guard LLM requires user confirmation."
        return "USER_CONFIRM", f"Unknown Guard LLM decision: {decision}"

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
                async with self._lock:
                    self._events[event.id] = replace(event, status="guard_checking")
                    guard_event = self._events[event.id]
                await self._broadcast(BrokerEnvelope("event-upsert", {"event": guard_event.to_dict()}).to_dict())

                decision = "deny"
                errno = "EPERM"
                if self._has_user_allow_grant(event):
                    guard_decision = "ALLOW"
                    guard_reason = "Allowed by recent user confirmation for the same action and target."
                else:
                    guard_decision, guard_reason = await self._guard_decision_for_event(event)
                LOG.info(
                    "Guard decision id=%s syscall=%s decision=%s reason=%s",
                    event.id,
                    event.syscall,
                    guard_decision,
                    guard_reason,
                )
                if guard_decision == "ALLOW":
                    decision = "allow"
                    errno = None
                    await self._set_status(event.id, "allowed", errno)
                else:
                    future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
                    async with self._lock:
                        self._pending[event.id] = future
                    await self._set_status(event.id, "pending", None)
                    try:
                        decision = await asyncio.wait_for(future, timeout=self.decision_timeout)
                        errno = None if decision == "allow" else "EPERM"
                    except asyncio.TimeoutError:
                        LOG.warning("Timed out waiting for user decision id=%s syscall=%s", event.id, event.syscall)
                        await self._set_status(event.id, "timeout", errno)
                    else:
                        LOG.info("User decision id=%s syscall=%s decision=%s", event.id, event.syscall, decision)
                        if decision == "allow":
                            self._remember_user_allow(event)
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
            self._events[event.id] = replace(event, status="guard_checking")
            updated = self._events[event.id]
        LOG.info(
            "Received syscall event id=%s syscall=%s pid=%s path=%s (file backend)",
            event.id,
            event.syscall,
            event.pid,
            event.path,
        )
        await self._broadcast(BrokerEnvelope("event-upsert", {"event": updated.to_dict()}).to_dict())
        self._start_task(self._guard_then_await_file_decision(event))

    async def _guard_then_await_file_decision(self, event: SyscallEvent) -> None:
        decision = "deny"
        errno = "EPERM"
        if self._has_user_allow_grant(event):
            guard_decision = "ALLOW"
            guard_reason = "Allowed by recent user confirmation for the same action and target."
        else:
            guard_decision, guard_reason = await self._guard_decision_for_event(event)
        LOG.info(
            "Guard decision id=%s syscall=%s decision=%s reason=%s (file backend)",
            event.id,
            event.syscall,
            guard_decision,
            guard_reason,
        )
        if guard_decision == "ALLOW":
            await self._write_decision_file(event.id, "allow", None)
            await self._set_status(event.id, "allowed", None)
            return

        future: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        async with self._lock:
            self._pending[event.id] = future
        await self._set_status(event.id, "pending", None)
        await self._await_file_decision(event.id, event.syscall, future)

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
            if decision == "allow":
                event = self._events.get(event_id)
                if event is not None:
                    self._remember_user_allow(event)
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
            if status not in {"pending", "guard_checking"}:
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

    async def set_auto_accept(self, enabled: bool) -> bool:
        async with self._lock:
            self._auto_accept = enabled
        await self._broadcast(await self.snapshot())
        return enabled

    async def snapshot(self) -> dict[str, Any]:
        async with self._lock:
            events = [event.to_dict() for event in self._events.values()]
            llm_exchanges = [exchange.to_dict() for exchange in self._llm_exchanges.values()]
            auto_accept = self._auto_accept
        return BrokerEnvelope(
            "snapshot",
            {"events": events, "llm_exchanges": llm_exchanges, "auto_accept": auto_accept},
        ).to_dict()

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

    async def auto_accept_handler(request: web.Request) -> web.Response:
        payload = await request.json()
        enabled = payload.get("enabled")
        if not isinstance(enabled, bool):
            raise web.HTTPBadRequest(text="enabled must be boolean")
        await broker.set_auto_accept(enabled)
        return web.json_response({"ok": True, "auto_accept": enabled})

    app.router.add_get("/", index)
    app.router.add_get("/api/health", health)
    app.router.add_get("/api/events", events_handler)
    app.router.add_get("/ws", websocket_handler)
    app.router.add_post("/api/events/{event_id}/decision", decide_handler)
    app.router.add_post("/api/auto-accept", auto_accept_handler)


async def create_app(
    socket_path: Path,
    decision_timeout: float,
    *,
    tcp_host: str | None = None,
    tcp_port: int | None = None,
    event_log_path: Path | None = None,
    decision_dir: Path | None = None,
    llm_log_path: Path | None = None,
    reason_pipeline_config: ReasonPipelineConfig | None = None,
) -> web.Application:
    broker = ApprovalBroker(
        socket_path=socket_path,
        decision_timeout=decision_timeout,
        tcp_host=tcp_host,
        tcp_port=tcp_port,
        event_log_path=event_log_path,
        decision_dir=decision_dir,
        llm_log_path=llm_log_path,
        reason_pipeline_config=reason_pipeline_config,
    )
    await broker.start()
    app = web.Application()
    app["broker"] = broker

    async def on_cleanup(_: web.Application) -> None:
        await broker.stop()

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
        reason_pipeline_config=build_reason_pipeline_config(args),
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
    LOG.info(
        "Broker ready on %s; approval IPC on %s",
        ", ".join(f"http://{host}:{args.web_port}" for host in hosts),
        ", ".join(approval_endpoints),
    )
    stop_event = asyncio.Event()
    loop = asyncio.get_running_loop()
    for signame in (signal.SIGTERM, signal.SIGINT):
        with suppress(NotImplementedError):
            loop.add_signal_handler(signame, stop_event.set)
    await stop_event.wait()
    await runner.cleanup()


def build_reason_pipeline_config(args: argparse.Namespace) -> ReasonPipelineConfig | None:
    if not args.reason_pipeline_dir:
        return None
    max_concurrency = max(1, int(args.reason_pipeline_max_concurrency))
    pipeline_dir = Path(args.reason_pipeline_dir)
    event_dir = Path(args.reason_pipeline_event_dir) if args.reason_pipeline_event_dir else pipeline_dir / "events"
    output_dir = (
        Path(args.reason_pipeline_output_dir)
        if args.reason_pipeline_output_dir
        else pipeline_dir / "normalized-events"
    )
    log_path = (
        Path(args.reason_pipeline_log_path)
        if args.reason_pipeline_log_path
        else pipeline_dir / "reason-pipeline.ndjson"
    )
    db_path = Path(args.reason_pipeline_db_path) if args.reason_pipeline_db_path else None
    return ReasonPipelineConfig(
        pipeline_dir=pipeline_dir,
        agent_name=args.reason_pipeline_agent_name,
        event_dir=event_dir,
        output_dir=output_dir,
        log_path=log_path,
        db_path=db_path,
        max_concurrency=max_concurrency,
    )
