import { useState } from "react";
import { motion, AnimatePresence } from "motion/react";
import { Clock, Shield, Terminal, AlertCircle, ChevronDown, ChevronUp } from "lucide-react";

export interface LogData {
  id: string;
  timestamp: Date;
  eventName: string;
  riskLevel: "harmful" | "ambiguous" | "normal";
  model: string;
  systemCall: string;
  description: string;
  riskReason?: string;
  requiresApproval?: boolean;
  approvalStatus?: "approved" | "rejected" | null;
  detailLogs?: string[];
}

interface LogCardProps {
  log: LogData;
  onApproval?: (logId: string, approved: boolean) => void;
  index?: number;
}

const riskConfig = {
  harmful: {
    label: "Harmful",
    bg: "bg-[var(--harmful-bg)]",
    border: "border-[var(--harmful)]",
    text: "text-[var(--harmful)]",
    icon: AlertCircle,
  },
  ambiguous: {
    label: "Ambiguous",
    bg: "bg-[var(--ambiguous-bg)]",
    border: "border-[var(--ambiguous)]",
    text: "text-[var(--ambiguous)]",
    icon: AlertCircle,
  },
  normal: {
    label: "Normal",
    bg: "bg-[var(--normal-bg)]",
    border: "border-[var(--normal)]",
    text: "text-[var(--normal)]",
    icon: Shield,
  },
};

export function LogCard({ log, onApproval, index = 0 }: LogCardProps) {
  const config = riskConfig[log.riskLevel];
  const RiskIcon = config.icon;
  const [isExpanded, setIsExpanded] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.05 }}
      className={`
        relative rounded-xl border-2 overflow-hidden
        ${config.bg} ${config.border}
        ${log.requiresApproval && !log.approvalStatus ? 'shadow-2xl ring-4 ring-yellow-400/40' : 'shadow-md'}
        transition-all duration-300 hover:shadow-lg
      `}
    >
      {/* Subtle overlay */}
      <div className="absolute inset-0 bg-gradient-to-br from-white/30 to-transparent pointer-events-none" />

      {/* Content */}
      <div className="relative p-4">
        {/* Compact Info Row - Clickable */}
        <div
          className="flex items-center justify-between gap-4 mb-3 cursor-pointer"
          onClick={() => setIsExpanded(!isExpanded)}
        >
          {/* Time */}
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-muted-foreground" />
            <span className="text-sm text-foreground font-mono">
              {log.timestamp.toLocaleString('ko-KR', {
                year: 'numeric',
                month: '2-digit',
                day: '2-digit',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
              })}
            </span>
          </div>

          {/* Risk Badge and Expand Icon */}
          <div className="flex items-center gap-2">
            <span className={`px-3 py-1 rounded-full text-xs font-semibold ${config.text} ${config.bg} border ${config.border}`}>
              {config.label}
            </span>
            {isExpanded ? (
              <ChevronUp className="w-5 h-5 text-slate-500" />
            ) : (
              <ChevronDown className="w-5 h-5 text-slate-500" />
            )}
          </div>
        </div>

        {/* Info Grid */}
        <div className="grid grid-cols-3 gap-4 mb-3">
          {/* Agent */}
          <div>
            <div className="text-xs text-muted-foreground mb-1">Agent</div>
            <div className="font-mono text-sm text-foreground font-medium">{log.model}</div>
          </div>

          {/* System Call */}
          <div>
            <div className="text-xs text-muted-foreground mb-1">시스템 호출</div>
            <div className="font-mono text-sm text-foreground font-medium">{log.systemCall}</div>
          </div>

          {/* Approval Status */}
          <div>
            <div className="text-xs text-muted-foreground mb-1">승인 여부</div>
            <div className="text-sm font-medium">
              {log.approvalStatus === "approved" && (
                <span className="text-emerald-600">승인됨</span>
              )}
              {log.approvalStatus === "rejected" && (
                <span className="text-red-600">거부됨</span>
              )}
              {!log.approvalStatus && log.requiresApproval && (
                <span className="text-amber-600">대기중</span>
              )}
              {!log.approvalStatus && !log.requiresApproval && (
                <span className="text-slate-500">-</span>
              )}
            </div>
          </div>
        </div>

        {log.riskReason && (
          <div className="mb-3 rounded-lg border border-slate-200 bg-white/70 px-3 py-2">
            <div className="text-xs text-muted-foreground mb-1">판단 이유</div>
            <div className="text-sm text-slate-700 leading-relaxed">{log.riskReason}</div>
          </div>
        )}

        {/* Approval Buttons */}
        {log.requiresApproval && !log.approvalStatus && onApproval && (
          <motion.div
            initial={{ opacity: 0, height: 0 }}
            animate={{ opacity: 1, height: 'auto' }}
            className="flex gap-3 pt-4 border-t border-border"
          >
            <button
              onClick={() => onApproval(log.id, true)}
              className="flex-1 px-4 py-2.5 bg-emerald-500 hover:bg-emerald-600 text-white font-semibold rounded-lg transition-all duration-200 hover:scale-105 active:scale-95 shadow-lg hover:shadow-xl"
            >
              승인 (Yes)
            </button>
            <button
              onClick={() => onApproval(log.id, false)}
              className="flex-1 px-4 py-2.5 bg-red-500 hover:bg-red-600 text-white font-semibold rounded-lg transition-all duration-200 hover:scale-105 active:scale-95 shadow-lg hover:shadow-xl"
            >
              거부 (No)
            </button>
          </motion.div>
        )}

        {/* Approval Status */}
        {log.approvalStatus && (
          <div className={`mt-3 px-4 py-2 rounded-lg text-sm font-semibold text-center ${
            log.approvalStatus === 'approved'
              ? 'bg-emerald-50 text-emerald-700 border border-emerald-300'
              : 'bg-red-50 text-red-700 border border-red-300'
          }`}>
            {log.approvalStatus === 'approved' ? '✓ 승인됨' : '✗ 거부됨'}
          </div>
        )}

        {/* Detailed Logs */}
        <AnimatePresence>
          {isExpanded && log.detailLogs && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              transition={{ duration: 0.3 }}
              className="mt-4 pt-4 border-t border-slate-200"
            >
              <h4 className="text-sm font-semibold text-slate-700 mb-3 flex items-center gap-2">
                <Terminal className="w-4 h-4" />
                상세 로그
              </h4>
              <div className="bg-slate-900 rounded-lg p-4 max-h-96 overflow-y-auto">
                <div className="font-mono text-xs space-y-1">
                  {log.detailLogs.map((logLine, idx) => (
                    <div key={idx} className="text-slate-300 break-all">
                      {logLine}
                    </div>
                  ))}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>
    </motion.div>
  );
}
