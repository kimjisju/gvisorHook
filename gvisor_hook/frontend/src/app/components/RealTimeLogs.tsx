import { AnimatePresence, motion } from "motion/react";
import { AlertTriangle } from "lucide-react";
import { LogCard, LogData } from "./LogCard";

interface RealTimeLogsProps {
  logs: LogData[];
  onApproval: (logId: string, approved: boolean) => void;
}

export function RealTimeLogs({ logs, onApproval }: RealTimeLogsProps) {
  return (
    <div className="h-full flex flex-col">
      <div className="mb-6">
        <h2 className="font-display font-bold text-3xl text-foreground">
          실시간 로그
        </h2>
      </div>

      <div className="flex-1 overflow-auto pr-2 space-y-4">
        {logs.length === 0 ? (
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
            {logs.map((log, index) => (
              <LogCard
                key={log.id}
                log={log}
                onApproval={onApproval}
                index={index}
              />
            ))}
          </AnimatePresence>
        )}
      </div>
    </div>
  );
}
