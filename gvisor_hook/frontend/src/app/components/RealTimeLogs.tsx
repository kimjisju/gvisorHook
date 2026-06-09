import { motion, AnimatePresence } from "motion/react";
import { LogCard, LogData } from "./LogCard";
import { AlertTriangle } from "lucide-react";

interface RealTimeLogsProps {
  logs: LogData[];
  onApproval: (logId: string, approved: boolean) => void;
}

export function RealTimeLogs({ logs, onApproval }: RealTimeLogsProps) {
  // Find logs requiring approval
  const pendingApproval = logs.find(log => log.requiresApproval && !log.approvalStatus);
  const displayLogs = logs.filter(log => !(log.requiresApproval && !log.approvalStatus));

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <h2 className="font-display font-bold text-3xl text-foreground">
          실시간 로그
        </h2>
      </div>

      {/* Approval Required Section */}
      <AnimatePresence mode="wait">
        {pendingApproval && (
          <motion.div
            initial={{ opacity: 0, y: -20, height: 0 }}
            animate={{ opacity: 1, y: 0, height: 'auto' }}
            exit={{ opacity: 0, y: -20, height: 0 }}
            className="mb-6"
          >
            <div className="bg-yellow-50 border-2 border-yellow-400 rounded-xl p-4 mb-4">
              <div className="flex items-center gap-3 mb-3">
                <AlertTriangle className="w-6 h-6 text-yellow-600 animate-pulse" />
                <div>
                  <h3 className="font-display font-bold text-lg text-yellow-700">
                    승인 필요
                  </h3>
                  <p className="text-sm text-slate-600">
                    다음 작업을 승인하거나 거부해주세요
                  </p>
                </div>
              </div>
            </div>
            <LogCard log={pendingApproval} onApproval={onApproval} />
          </motion.div>
        )}
      </AnimatePresence>

      {/* Regular Logs */}
      <div className="flex-1 overflow-auto pr-2 space-y-4">
        {displayLogs.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="h-full flex items-center justify-center"
          >
            <div className="text-center">
              <div className="w-24 h-24 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <motion.div
                  animate={{
                    scale: [1, 1.2, 1],
                    opacity: [0.5, 1, 0.5],
                  }}
                  transition={{
                    duration: 2,
                    repeat: Infinity,
                    ease: "easeInOut",
                  }}
                >
                  <AlertTriangle className="w-12 h-12 text-slate-400" />
                </motion.div>
              </div>
              <h3 className="font-display font-semibold text-xl text-foreground mb-2">
                표시할 로그가 없습니다
              </h3>
              <p className="text-muted-foreground">
                새로운 로그가 들어올 때까지 대기 중입니다
              </p>
            </div>
          </motion.div>
        ) : (
          <AnimatePresence>
            {displayLogs.map((log) => (
              <LogCard
                key={log.id}
                log={log}
                onApproval={onApproval}
                index={0}
              />
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
