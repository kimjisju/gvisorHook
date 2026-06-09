import { useState, useMemo } from "react";
import { motion } from "motion/react";
import { LogCard, LogData } from "./LogCard";
import { Search, Filter, Calendar, AlertCircle } from "lucide-react";

interface LogHistoryProps {
  logs: LogData[];
}

type RiskFilter = "all" | "harmful" | "ambiguous" | "normal";
type SortOrder = "newest" | "oldest";

export function LogHistory({ logs }: LogHistoryProps) {
  const [searchTerm, setSearchTerm] = useState("");
  const [riskFilter, setRiskFilter] = useState<RiskFilter>("all");
  const [sortOrder, setSortOrder] = useState<SortOrder>("newest");

  const filteredAndSortedLogs = useMemo(() => {
    let result = [...logs];

    // Apply search filter
    if (searchTerm) {
      const term = searchTerm.toLowerCase();
      result = result.filter(
        log =>
          log.eventName.toLowerCase().includes(term) ||
          log.description.toLowerCase().includes(term) ||
          log.id.toLowerCase().includes(term)
      );
    }

    // Apply risk filter
    if (riskFilter !== "all") {
      result = result.filter(log => log.riskLevel === riskFilter);
    }

    // Apply sorting
    result.sort((a, b) => {
      const timeA = a.timestamp.getTime();
      const timeB = b.timestamp.getTime();
      return sortOrder === "newest" ? timeB - timeA : timeA - timeB;
    });

    return result;
  }, [logs, searchTerm, riskFilter, sortOrder]);

  const riskFilterOptions: { value: RiskFilter; label: string }[] = [
    { value: "all", label: "전체" },
    { value: "harmful", label: "위험" },
    { value: "ambiguous", label: "애매함" },
    { value: "normal", label: "정상" },
  ];

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <h2 className="font-display font-bold text-3xl text-foreground">
          로그 히스토리
        </h2>
      </div>

      {/* Filters */}
      <div className="mb-6 space-y-4">
        {/* Search */}
        <div className="relative">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-muted-foreground" />
          <input
            type="text"
            placeholder="이벤트명, 설명, 로그 ID로 검색..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-12 pr-4 py-3 bg-white border border-slate-300 rounded-xl text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-blue-500/50 transition-all"
          />
        </div>

        {/* Filters Row */}
        <div className="flex gap-4">
          {/* Risk Filter */}
          <div className="flex-1">
            <label className="block text-sm font-semibold text-muted-foreground mb-2 flex items-center gap-2">
              <Filter className="w-4 h-4" />
              위험도
            </label>
            <div className="flex gap-2">
              {riskFilterOptions.map((option) => (
                <button
                  key={option.value}
                  onClick={() => setRiskFilter(option.value)}
                  className={`
                    flex-1 px-4 py-2 rounded-lg font-semibold text-sm transition-all
                    ${riskFilter === option.value
                      ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
                      : 'bg-white text-slate-700 hover:bg-slate-50 border border-slate-300'
                    }
                  `}
                >
                  {option.label}
                </button>
              ))}
            </div>
          </div>

          {/* Sort Order */}
          <div className="flex-1">
            <label className="block text-sm font-semibold text-muted-foreground mb-2 flex items-center gap-2">
              <Calendar className="w-4 h-4" />
              정렬
            </label>
            <div className="flex gap-2">
              <button
                onClick={() => setSortOrder("newest")}
                className={`
                  flex-1 px-4 py-2 rounded-lg font-semibold text-sm transition-all
                  ${sortOrder === "newest"
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
                    : 'bg-white text-slate-700 hover:bg-slate-50 border border-slate-300'
                  }
                `}
              >
                최신순
              </button>
              <button
                onClick={() => setSortOrder("oldest")}
                className={`
                  flex-1 px-4 py-2 rounded-lg font-semibold text-sm transition-all
                  ${sortOrder === "oldest"
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-500/20'
                    : 'bg-white text-slate-700 hover:bg-slate-50 border border-slate-300'
                  }
                `}
              >
                오래된순
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Results Count */}
      <div className="mb-4 text-sm text-muted-foreground">
        총 <span className="text-foreground font-semibold">{filteredAndSortedLogs.length}</span>개의 로그
      </div>

      {/* Logs List */}
      <div className="flex-1 overflow-auto pr-2 space-y-4">
        {filteredAndSortedLogs.length === 0 ? (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="h-full flex items-center justify-center"
          >
            <div className="text-center">
              <div className="w-24 h-24 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-4">
                <AlertCircle className="w-12 h-12 text-slate-400" />
              </div>
              <h3 className="font-display font-semibold text-xl text-foreground mb-2">
                표시할 로그가 없습니다
              </h3>
              <p className="text-muted-foreground">
                다른 필터 조건을 시도해보세요
              </p>
            </div>
          </motion.div>
        ) : (
          filteredAndSortedLogs.map((log, index) => (
            <LogCard key={log.id} log={log} index={index} />
          ))
        )}
      </div>
    </div>
  );
}
