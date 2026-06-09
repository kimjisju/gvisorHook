import { useState, useMemo } from "react";
import { motion } from "motion/react";
import {
  PieChart,
  Pie,
  Cell,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
  ResponsiveContainer,
} from "recharts";
import { LogData } from "./LogCard";
import { TrendingUp, AlertTriangle, Shield, Clock } from "lucide-react";

interface StatisticsProps {
  historicalLogs: LogData[];
  realtimeLogs: LogData[];
}

type DateFilter = "today" | "yesterday" | "twoDaysAgo";

export function Statistics({ historicalLogs, realtimeLogs }: StatisticsProps) {
  const [dateFilter, setDateFilter] = useState<DateFilter>("today");

  const dateFilterOptions: { value: DateFilter; label: string }[] = [
    { value: "twoDaysAgo", label: "2일 전" },
    { value: "yesterday", label: "1일 전" },
    { value: "today", label: "오늘" },
  ];

  const getDateThreshold = (filter: DateFilter): Date => {
    const now = new Date();
    const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());

    switch (filter) {
      case "today":
        return today;
      case "yesterday":
        return new Date(today.getTime() - 24 * 60 * 60 * 1000);
      case "twoDaysAgo":
        return new Date(today.getTime() - 2 * 24 * 60 * 60 * 1000);
    }
  };

  const getDateEndThreshold = (filter: DateFilter): Date => {
    const threshold = getDateThreshold(filter);
    return new Date(threshold.getTime() + 24 * 60 * 60 * 1000);
  };

  const stats = useMemo(() => {
    const startDate = getDateThreshold(dateFilter);
    const endDate = getDateEndThreshold(dateFilter);

    // Combine logs based on date filter
    const allLogs = dateFilter === "today"
      ? [...historicalLogs, ...realtimeLogs]
      : historicalLogs;

    const logsInRange = allLogs.filter(
      log => log.timestamp >= startDate && log.timestamp < endDate
    );

    const totalLogs = logsInRange.length;
    const harmfulCount = logsInRange.filter(l => l.riskLevel === "harmful").length;
    const ambiguousCount = logsInRange.filter(l => l.riskLevel === "ambiguous").length;
    const normalCount = logsInRange.filter(l => l.riskLevel === "normal").length;

    const approvalRequiredCount = logsInRange.filter(l => l.requiresApproval).length;
    const approvedCount = logsInRange.filter(l => l.approvalStatus === "approved").length;
    const rejectedCount = logsInRange.filter(l => l.approvalStatus === "rejected").length;

    // Time-based distribution (hourly)
    const hourlyDistribution = Array.from({ length: 24 }, (_, hour) => {
      const count = logsInRange.filter(log => log.timestamp.getHours() === hour).length;
      return {
        hour: `${hour}:00`,
        count,
      };
    });

    return {
      totalLogs,
      harmfulCount,
      ambiguousCount,
      normalCount,
      approvalRequiredCount,
      approvedCount,
      rejectedCount,
      hourlyDistribution,
    };
  }, [historicalLogs, realtimeLogs, dateFilter]);

  const riskPieData = [
    { name: "위험", value: stats.harmfulCount, color: "#ef4444" },
    { name: "애매함", value: stats.ambiguousCount, color: "#f59e0b" },
    { name: "정상", value: stats.normalCount, color: "#14b8a6" },
  ].filter(item => item.value > 0);

  const riskBarData = [
    { name: "위험", count: stats.harmfulCount, fill: "#ef4444" },
    { name: "애매함", count: stats.ambiguousCount, fill: "#f59e0b" },
    { name: "정상", count: stats.normalCount, fill: "#14b8a6" },
  ];

  const approvalData = [
    { name: "승인 필요", count: stats.approvalRequiredCount, fill: "#f59e0b" },
    { name: "승인됨", count: stats.approvedCount, fill: "#14b8a6" },
    { name: "거부됨", count: stats.rejectedCount, fill: "#ef4444" },
  ].filter(item => item.count > 0);

  const StatCard = ({ title, value, icon: Icon, color }: any) => (
    <motion.div
      initial={{ opacity: 0, scale: 0.9 }}
      animate={{ opacity: 1, scale: 1 }}
      className="bg-white border border-slate-200 rounded-xl p-6 shadow-lg hover:shadow-xl transition-all"
    >
      <div className="flex items-start justify-between">
        <div>
          <p className="text-sm text-muted-foreground mb-2">{title}</p>
          <p className="text-3xl font-bold text-foreground font-display">{value}</p>
        </div>
        <div
          className="p-3 rounded-xl"
          style={{
            backgroundColor: `${color}20`,
            borderColor: `${color}40`,
            borderWidth: '1px'
          }}
        >
          <Icon className="w-6 h-6" style={{ color }} />
        </div>
      </div>
    </motion.div>
  );

  return (
    <div className="h-full flex flex-col">
      {/* Header */}
      <div className="mb-6">
        <h2 className="font-display font-bold text-3xl text-foreground">
          통계
        </h2>
      </div>

      {/* Date Filter */}
      <div className="mb-6">
        <label className="block text-sm font-semibold text-muted-foreground mb-3">
          날짜 선택
        </label>
        <div className="flex gap-3">
          {dateFilterOptions.map((option) => (
            <button
              key={option.value}
              onClick={() => setDateFilter(option.value)}
              className={`
                flex-1 px-6 py-3 rounded-xl font-semibold transition-all
                ${dateFilter === option.value
                  ? 'bg-gradient-to-r from-blue-600 to-cyan-600 text-white shadow-lg shadow-blue-500/20'
                  : 'bg-white text-slate-700 hover:bg-slate-50 border border-slate-300'
                }
              `}
            >
              {option.label}
            </button>
          ))}
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <StatCard
          title="전체 로그 수"
          value={stats.totalLogs}
          icon={TrendingUp}
          color="#3b82f6"
        />
        <StatCard
          title="위험 로그"
          value={stats.harmfulCount}
          icon={AlertTriangle}
          color="#ef4444"
        />
        <StatCard
          title="승인 필요"
          value={stats.approvalRequiredCount}
          icon={Shield}
          color="#f59e0b"
        />
        <StatCard
          title="승인됨"
          value={stats.approvedCount}
          icon={Shield}
          color="#14b8a6"
        />
      </div>

      {/* Charts */}
      <div className="flex-1 overflow-auto pr-2">
        <div className="grid grid-cols-2 gap-6 mb-6">
          {/* Pie Chart - Risk Distribution */}
          <div className="bg-white border border-slate-200 rounded-xl p-6">
            <h3 className="font-display font-semibold text-lg text-foreground mb-4">
              위험도별 분포
            </h3>
            {riskPieData.length > 0 ? (
              <ResponsiveContainer width="100%" height={250}>
                <PieChart>
                  <Pie
                    data={riskPieData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {riskPieData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      backgroundColor: '#1e293b',
                      border: '1px solid #334155',
                      borderRadius: '8px',
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-[250px] flex items-center justify-center text-muted-foreground">
                데이터 없음
              </div>
            )}
          </div>

          {/* Bar Chart - Risk Counts */}
          <div className="bg-white border border-slate-200 rounded-xl p-6">
            <h3 className="font-display font-semibold text-lg text-foreground mb-4">
              위험도별 로그 수
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={riskBarData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis dataKey="name" stroke="#64748b" />
                <YAxis stroke="#64748b" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #e2e8f0',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="count" radius={[8, 8, 0, 0]}>
                  {riskBarData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Approval Stats */}
        {approvalData.length > 0 && (
          <div className="bg-white border border-slate-200 rounded-xl p-6 mb-6">
            <h3 className="font-display font-semibold text-lg text-foreground mb-4">
              승인 요청 현황
            </h3>
            <ResponsiveContainer width="100%" height={250}>
              <BarChart data={approvalData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                <XAxis type="number" stroke="#64748b" />
                <YAxis dataKey="name" type="category" stroke="#64748b" />
                <Tooltip
                  contentStyle={{
                    backgroundColor: '#ffffff',
                    border: '1px solid #e2e8f0',
                    borderRadius: '8px',
                  }}
                />
                <Bar dataKey="count" radius={[0, 8, 8, 0]}>
                  {approvalData.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.fill} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        )}

        {/* Time-based Trend */}
        <div className="bg-white border border-slate-200 rounded-xl p-6">
          <h3 className="font-display font-semibold text-lg text-foreground mb-4 flex items-center gap-2">
            <Clock className="w-5 h-5" />
            시간대별 로그 발생 추이
          </h3>
          <ResponsiveContainer width="100%" height={300}>
            <LineChart data={stats.hourlyDistribution}>
              <CartesianGrid strokeDasharray="3 3" stroke="#334155" />
              <XAxis dataKey="hour" stroke="#64748b" />
              <YAxis stroke="#64748b" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#1e293b',
                  border: '1px solid #334155',
                  borderRadius: '8px',
                }}
              />
              <Line
                type="monotone"
                dataKey="count"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={{ fill: '#3b82f6', r: 4 }}
                activeDot={{ r: 6 }}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  );
}
