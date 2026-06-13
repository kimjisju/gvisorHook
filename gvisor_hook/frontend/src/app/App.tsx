import { useState, useEffect, useCallback, useMemo, useRef } from "react";
import { motion } from "motion/react";
import { Sidebar, View } from "./components/Sidebar";
import { RealTimeLogs } from "./components/RealTimeLogs";
import { LogHistory } from "./components/LogHistory";
import { Statistics } from "./components/Statistics";
import { LogData } from "./components/LogCard";
import { LoginModal } from "./components/auth/LoginModal";
import { SignupModal } from "./components/auth/SignupModal";
import { EmailVerificationModal } from "./components/auth/EmailVerificationModal";
import { UserCircle } from "lucide-react";

type EventStatus = "guard_checking" | "pending" | "allowed" | "denied" | "timeout" | "error";

interface SyscallEvent {
  id: string;
  container_id: string;
  pid: number;
  tid: number;
  syscall: string;
  summary: string;
  path?: string | null;
  argv?: string[] | null;
  started_at: string;
  status: EventStatus;
  errno?: string | null;
  guard_decision?: string | null;
  guard_reason?: string | null;
  risk_level?: "harmful" | "ambiguous" | "normal" | null;
  agent_message?: string | null;
}

interface SnapshotPayload {
  events: SyscallEvent[];
  auto_accept: boolean;
}

interface AuthUser {
  id: number;
  name: string;
  email: string;
}

interface GuardActionRecord {
  id: number;
  agent_name?: string | null;
  event_id?: string | null;
  created_at?: string | null;
  syscall?: string | null;
  path?: string | null;
  argv?: string | null;
  raw_summary?: string | null;
  summary?: string | null;
  meaning?: string | null;
  normalized_action?: string | null;
  target_class?: string | null;
  rule_result?: string | null;
}

interface GuardRunRecord {
  id: number;
  user_id?: number | null;
  agent_name?: string | null;
  user_prompt?: string | null;
  ai_agent_reasoning?: string | null;
  rule_base_result?: string | null;
  rule_base_reason?: string | null;
  guard_llm_result?: string | null;
  guard_llm_reason?: string | null;
  final_decision?: string | null;
  approval_status?: string | null;
  approved_at?: string | null;
  created_at?: string | null;
  actions?: GuardActionRecord[];
}

type BrokerEnvelope =
  | { type: "snapshot"; payload: SnapshotPayload }
  | { type: "event-upsert"; payload: { event: SyscallEvent } }
  | { type: "llm-upsert"; payload: unknown };

const API_BASE_URL = (((import.meta as any).env?.VITE_API_BASE_URL as string | undefined) || "http://localhost:5000").replace(/\/$/, "");

function sortEvents(events: SyscallEvent[]): SyscallEvent[] {
  return [...events].sort((a, b) => {
    return (new Date(b.started_at).getTime() || 0) - (new Date(a.started_at).getTime() || 0);
  });
}

function riskLevelFor(event: SyscallEvent): LogData["riskLevel"] {
  if (event.risk_level) return event.risk_level;
  if (event.status === "error" || event.status === "timeout") return "ambiguous";
  return event.status === "allowed" ? "normal" : "harmful";
}

function toLogData(event: SyscallEvent): LogData {
  const detailLogs = [
    `event_id=${event.id}`,
    `container=${event.container_id}`,
    `pid=${event.pid} tid=${event.tid}`,
    `status=${event.status}`,
    `syscall=${event.syscall}`,
    event.path ? `path=${event.path}` : "",
    event.argv?.length ? `argv=${event.argv.join(" ")}` : "",
    event.guard_decision ? `guard_decision=${event.guard_decision}` : "",
    event.guard_reason ? `guard_reason=${event.guard_reason}` : "",
    event.risk_level ? `risk_level=${event.risk_level}` : "",
    event.errno ? `errno=${event.errno}` : "",
    event.agent_message ? `agent_message=${event.agent_message}` : "",
    `started_at=${event.started_at}`,
  ].filter(Boolean);

  return {
    id: event.id,
    timestamp: new Date(event.started_at),
    eventName: event.summary || "시스템 호출 감지",
    riskLevel: riskLevelFor(event),
    model: event.container_id || "gVisor",
    systemCall: event.syscall,
    description: event.summary || "시스템 호출 이벤트가 감지되었습니다.",
    riskReason: event.guard_reason || undefined,
    requiresApproval: event.status === "pending",
    approvalStatus:
      event.status === "allowed" ? "approved" : event.status === "denied" ? "rejected" : null,
    detailLogs,
  };
}

function riskLevelForGuardRun(run: GuardRunRecord, action?: GuardActionRecord): LogData["riskLevel"] {
  const risk = run.rule_base_result?.toLowerCase();
  if (risk === "harmful" || risk === "ambiguous" || risk === "normal") return risk;

  const result = (action?.rule_result || run.guard_llm_result || run.final_decision || "").toLowerCase();
  if (result.includes("allow") || result === "approved") return "normal";
  if (result.includes("timeout") || result.includes("error")) return "ambiguous";
  return "harmful";
}

function approvalStatusForGuardRun(run: GuardRunRecord): LogData["approvalStatus"] {
  if (run.approval_status === "approved") return "approved";
  if (run.approval_status === "rejected") return "rejected";
  if (run.final_decision === "allow") return "approved";
  if (run.final_decision === "deny") return "rejected";
  return null;
}

function toSavedLogData(run: GuardRunRecord): LogData {
  const action = run.actions?.[0];
  const logId = action?.event_id || `guard-run-${run.id}`;
  const timestamp = new Date(action?.created_at || run.created_at || Date.now());
  const systemCall = action?.syscall || action?.normalized_action || "unknown";
  const summary = action?.summary || action?.raw_summary || run.user_prompt || "저장된 시스템 호출 로그";
  const approvalStatus = approvalStatusForGuardRun(run);
  const detailLogs = [
    `source=supabase`,
    `guard_run_id=${run.id}`,
    run.user_id ? `user_id=${run.user_id}` : "",
    action?.event_id ? `event_id=${action.event_id}` : "",
    run.final_decision ? `final_decision=${run.final_decision}` : "",
    run.approval_status ? `approval_status=${run.approval_status}` : "",
    systemCall ? `syscall=${systemCall}` : "",
    action?.path ? `path=${action.path}` : "",
    action?.argv ? `argv=${action.argv}` : "",
    run.guard_llm_result ? `guard_llm_result=${run.guard_llm_result}` : "",
    run.guard_llm_reason ? `guard_llm_reason=${run.guard_llm_reason}` : "",
    run.rule_base_result ? `rule_base_result=${run.rule_base_result}` : "",
    run.rule_base_reason ? `rule_base_reason=${run.rule_base_reason}` : "",
    run.created_at ? `created_at=${run.created_at}` : "",
  ].filter(Boolean);

  return {
    id: logId,
    timestamp,
    eventName: summary,
    riskLevel: riskLevelForGuardRun(run, action),
    model: run.agent_name || action?.agent_name || "gVisor",
    systemCall,
    description: summary,
    riskReason: run.guard_llm_reason || run.rule_base_reason || action?.meaning || undefined,
    requiresApproval: run.approval_status === "pending",
    approvalStatus,
    detailLogs,
  };
}

function mergeLogs(savedLogs: LogData[], liveLogs: LogData[]): LogData[] {
  const byId = new Map<string, LogData>();
  for (const log of savedLogs) byId.set(log.id, log);
  for (const log of liveLogs) byId.set(log.id, log);
  return [...byId.values()].sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
}

export default function App() {
  const [currentView, setCurrentView] = useState<View>("realtime");
  const [events, setEvents] = useState<SyscallEvent[]>([]);
  const [savedLogs, setSavedLogs] = useState<LogData[]>([]);
  const [wsConnected, setWsConnected] = useState(false);
  const [authUser, setAuthUser] = useState<AuthUser | null>(null);
  const focusedIdRef = useRef<string | null>(null);
  const wsConnectedRef = useRef(false);

  const logs = useMemo(() => sortEvents(events).map(toLogData), [events]);
  const historyLogs = useMemo(() => mergeLogs(savedLogs, logs), [savedLogs, logs]);

  // Auth modal states
  const [showLoginModal, setShowLoginModal] = useState(false);
  const [showSignupModal, setShowSignupModal] = useState(false);
  const [showEmailVerificationModal, setShowEmailVerificationModal] = useState(false);
  const [verificationEmail, setVerificationEmail] = useState("");
  const [verificationUrl, setVerificationUrl] = useState("");

  const syncCurrentUser = useCallback(async (user: AuthUser | null) => {
    try {
      await fetch("/api/current-user", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ user_id: user?.id ?? null }),
      });
    } catch {
      // The UI can still run; only DB attribution is unavailable until the broker accepts the user id.
    }
  }, []);

  const loadSavedLogs = useCallback(async (user: AuthUser | null) => {
    if (!user) {
      setSavedLogs([]);
      return;
    }

    try {
      const response = await fetch(`${API_BASE_URL}/guard-runs?user_id=${encodeURIComponent(user.id)}`, {
        cache: "no-store",
      });
      if (!response.ok) return;
      const guardRuns = (await response.json()) as GuardRunRecord[];
      setSavedLogs(guardRuns.map(toSavedLogData));
    } catch {
      // Historical DB logs are best-effort; realtime logs should not be blocked by DB/API failures.
    }
  }, []);

  useEffect(() => {
    const savedAuth =
      window.localStorage.getItem("gvisor_hook_auth") ||
      window.sessionStorage.getItem("gvisor_hook_auth");
    if (!savedAuth) return;
    try {
      const payload = JSON.parse(savedAuth);
      if (payload?.user) {
        setAuthUser(payload.user);
        syncCurrentUser(payload.user);
        loadSavedLogs(payload.user);
      }
    } catch {
      // Ignore stale or manually edited storage.
    }
  }, [loadSavedLogs, syncCurrentUser]);

  useEffect(() => {
    focusedIdRef.current = logs.find((log) => log.requiresApproval && !log.approvalStatus)?.id ?? null;
  }, [logs]);

  const applyEnvelope = useCallback((envelope: BrokerEnvelope) => {
    if (envelope.type === "snapshot") {
      setEvents(envelope.payload.events || []);
      return;
    }

    if (envelope.type === "event-upsert") {
      setEvents((prev) => {
        const next = [...prev];
        const index = next.findIndex((event) => event.id === envelope.payload.event.id);
        if (index >= 0) {
          next[index] = envelope.payload.event;
        } else {
          next.push(envelope.payload.event);
        }
        return next;
      });
    }
  }, []);

  const refreshSnapshot = useCallback(async () => {
    try {
      const response = await fetch("/api/events", { cache: "no-store" });
      if (response.ok) {
        applyEnvelope((await response.json()) as BrokerEnvelope);
      }
    } catch {
      // Snapshot polling is best-effort; the websocket reconnect loop owns connection state.
    }
  }, [applyEnvelope]);

  useEffect(() => {
    let cancelled = false;
    let socket: WebSocket | null = null;
    let retryTimer: number | null = null;

    const connect = () => {
      if (cancelled) return;
      const protocol = window.location.protocol === "https:" ? "wss" : "ws";
      socket = new WebSocket(`${protocol}://${window.location.host}/ws`);

      socket.onopen = () => {
        wsConnectedRef.current = true;
        setWsConnected(true);
      };
      socket.onclose = () => {
        wsConnectedRef.current = false;
        setWsConnected(false);
        if (!cancelled) retryTimer = window.setTimeout(connect, 1000);
      };
      socket.onerror = () => socket?.close();
      socket.onmessage = (message) => applyEnvelope(JSON.parse(message.data) as BrokerEnvelope);
    };

    refreshSnapshot();
    connect();

    const pollTimer = window.setInterval(() => {
      if (!wsConnectedRef.current) refreshSnapshot();
    }, 1000);

    return () => {
      cancelled = true;
      window.clearInterval(pollTimer);
      if (retryTimer !== null) window.clearTimeout(retryTimer);
      socket?.close();
    };
  }, [applyEnvelope, refreshSnapshot]);

  const handleApproval = useCallback(
    async (logId: string, approved: boolean) => {
      await fetch(`/api/events/${encodeURIComponent(logId)}/decision`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision: approved ? "allow" : "deny" }),
      });
      if (!wsConnectedRef.current) await refreshSnapshot();
    },
    [refreshSnapshot]
  );

  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (!focusedIdRef.current) return;
      if (event.key === "y" || event.key === "Y") handleApproval(focusedIdRef.current, true);
      if (event.key === "n" || event.key === "N") handleApproval(focusedIdRef.current, false);
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [handleApproval]);

  const handleEmailVerification = (email: string, verifyUrl?: string) => {
    setVerificationEmail(email);
    setVerificationUrl(verifyUrl || "");
    setShowSignupModal(false);
    setShowEmailVerificationModal(true);
  };

  return (
    <div className="size-full flex bg-gradient-to-br from-slate-50 via-white to-slate-50">
      {/* Background Effects */}
      <div className="fixed inset-0 pointer-events-none">
        <div className="absolute top-0 left-1/4 w-96 h-96 bg-blue-500/5 rounded-full blur-3xl" />
        <div className="absolute bottom-0 right-1/4 w-96 h-96 bg-cyan-500/5 rounded-full blur-3xl" />
      </div>

      {/* Sidebar */}
      <Sidebar currentView={currentView} onViewChange={setCurrentView} user={authUser} />

      {/* Main Content */}
      <main className="flex-1 overflow-hidden relative">
        <div className="h-full p-8 overflow-auto">
          <motion.div
            key={currentView}
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: -20 }}
            transition={{ duration: 0.3 }}
            className="h-full"
          >
            {currentView === "realtime" && <RealTimeLogs logs={logs} onApproval={handleApproval} />}
            {currentView === "history" && <LogHistory logs={historyLogs} />}
            {currentView === "statistics" && <Statistics historicalLogs={historyLogs} realtimeLogs={[]} />}
          </motion.div>
        </div>
      </main>

      <div
        className={`fixed top-4 right-4 z-40 rounded-full px-3 py-1.5 text-xs font-semibold shadow-sm ${
          wsConnected ? "bg-emerald-50 text-emerald-700" : "bg-amber-50 text-amber-700"
        }`}
      >
        {wsConnected ? "Connected" : "Reconnecting"}
      </div>

      {/* Auth Button - Floating */}
      <button
        onClick={() => setShowLoginModal(true)}
        className="fixed bottom-6 right-6 p-4 bg-gradient-to-r from-blue-600 to-cyan-600 text-white rounded-full shadow-lg hover:shadow-xl hover:scale-110 transition-all duration-200 z-40"
        title="로그인"
      >
        <UserCircle className="w-6 h-6" />
      </button>

      {/* Auth Modals */}
      <LoginModal
        isOpen={showLoginModal}
        onClose={() => setShowLoginModal(false)}
        onSwitchToSignup={() => {
          setShowLoginModal(false);
          setShowSignupModal(true);
        }}
        onLoginSuccess={(user) => {
          setAuthUser(user);
          syncCurrentUser(user);
          loadSavedLogs(user);
          setShowLoginModal(false);
        }}
      />
      <SignupModal
        isOpen={showSignupModal}
        onClose={() => setShowSignupModal(false)}
        onSwitchToLogin={() => {
          setShowSignupModal(false);
          setShowLoginModal(true);
        }}
        onEmailVerification={handleEmailVerification}
      />
      <EmailVerificationModal
        isOpen={showEmailVerificationModal}
        onClose={() => setShowEmailVerificationModal(false)}
        email={verificationEmail}
        verifyUrl={verificationUrl}
        onSwitchToLogin={() => {
          setShowEmailVerificationModal(false);
          setShowLoginModal(true);
        }}
      />
    </div>
  );
}
