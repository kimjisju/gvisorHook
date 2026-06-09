import { motion } from "motion/react";
import { Activity, History, BarChart3 } from "lucide-react";

export type View = "realtime" | "history" | "statistics";

interface SidebarProps {
  currentView: View;
  onViewChange: (view: View) => void;
}

const menuItems = [
  {
    id: "realtime" as View,
    label: "실시간 로그",
    icon: Activity,
  },
  {
    id: "history" as View,
    label: "로그 히스토리",
    icon: History,
  },
  {
    id: "statistics" as View,
    label: "통계",
    icon: BarChart3,
  },
];

export function Sidebar({ currentView, onViewChange }: SidebarProps) {
  return (
    <div className="w-72 h-full bg-gradient-to-b from-slate-50 to-slate-100 border-r border-slate-200 flex flex-col">
      {/* Header */}
      <div className="p-6 border-b border-slate-200">
        <div className="flex items-center gap-3 mb-2">
          <div className="w-10 h-10 bg-gradient-to-br from-blue-500 to-cyan-500 rounded-xl flex items-center justify-center shadow-lg shadow-blue-500/20">
            <Activity className="w-6 h-6 text-white" />
          </div>
          <div>
            <h1 className="font-display font-bold text-xl text-slate-900 leading-tight tracking-wide">
              ARGUS
            </h1>
          </div>
        </div>
      </div>

      {/* Navigation */}
      <nav className="flex-1 p-4 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = currentView === item.id;

          return (
            <motion.button
              key={item.id}
              onClick={() => onViewChange(item.id)}
              className={`
                w-full px-4 py-4 rounded-xl flex items-center gap-4
                transition-all duration-300 relative overflow-hidden group
                ${isActive
                  ? 'bg-gradient-to-r from-blue-600 to-cyan-600 shadow-lg shadow-blue-500/20'
                  : 'bg-white hover:bg-slate-50 border border-slate-200'
                }
              `}
              whileHover={{ scale: 1.02 }}
              whileTap={{ scale: 0.98 }}
            >
              {/* Active indicator */}
              {isActive && (
                <motion.div
                  layoutId="activeIndicator"
                  className="absolute left-0 top-0 bottom-0 w-1 bg-white rounded-r"
                  transition={{ type: "spring", stiffness: 300, damping: 30 }}
                />
              )}

              {/* Background glow for active */}
              {isActive && (
                <div className="absolute inset-0 bg-gradient-to-r from-blue-400/10 to-cyan-400/10 blur-xl" />
              )}

              <div className={`
                p-2 rounded-lg relative z-10
                ${isActive
                  ? 'bg-white/20'
                  : 'bg-slate-100 group-hover:bg-slate-200'
                }
              `}>
                <Icon className={`w-5 h-5 ${isActive ? 'text-white' : 'text-slate-600'}`} />
              </div>

              <div className="flex-1 text-left relative z-10">
                <div className={`font-semibold ${isActive ? 'text-white' : 'text-slate-700'}`}>
                  {item.label}
                </div>
              </div>
            </motion.button>
          );
        })}
      </nav>

    </div>
  );
}
