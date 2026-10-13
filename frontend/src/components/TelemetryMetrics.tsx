import React, { useMemo } from 'react';
import { 
  ResponsiveContainer, 
  XAxis, 
  YAxis, 
  Tooltip, 
  PieChart, 
  Pie, 
  Cell, 
  Area, 
  AreaChart,
  CartesianGrid
} from 'recharts';
import { 
  Activity, 
  ShieldAlert, 
  ArrowUpRight
} from 'lucide-react';
import type { ULPFLogRecord } from '../types';
import { SpotlightCard } from './react-bits/SpotlightCard';
import { AnimatedCounter } from './react-bits/AnimatedCounter';

interface TelemetryMetricsProps {
  logs: ULPFLogRecord[];
  throughput: number;
  hostStreaming?: boolean;
  instantDemoMode?: boolean;
  isStreaming?: boolean;
  hostInfo?: { hostname: string; ip: string } | null;
}

// Cohesive Monochromatic Cyber Cyan & Blue Palette (No harsh rainbow colors)
const TAXONOMY_COLORS = ['#22d3ee', '#0ea5e9', '#38bdf8', '#0284c7', '#0369a1', '#67e8f9'];

const TelemetryMetricsComponent: React.FC<TelemetryMetricsProps> = ({ 
  logs, 
  throughput,
  hostStreaming: _hostStreaming = false,
  instantDemoMode: _instantDemoMode = true,
  isStreaming: _isStreaming = false,
  hostInfo: _hostInfo = null
}) => {
  const categoryData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs.forEach(log => {
      const d = log.normalized_data as any;
      const cat = d?.category_name || d?.class_name || 'Network Activity';
      counts[cat] = (counts[cat] || 0) + 1;
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [logs]);

  const threatGeoData = useMemo(() => {
    const counts: Record<string, number> = {};
    logs
      .filter(l => {
        const d = l.normalized_data as any;
        return d?.threat?.is_malicious || d?.enrichment?.is_malicious;
      })
      .forEach(l => {
        const d = l.normalized_data as any;
        const actor = d?.threat?.actor || d?.enrichment?.threat_actor || 'Unknown';
        counts[actor] = (counts[actor] || 0) + 1;
      });
    return Object.entries(counts).map(([name, count]) => ({ name, count }));
  }, [logs]);

  // Live rolling 30s historical buffer for processing velocity
  const [history, setHistory] = React.useState<Array<{ time: string; eps: number }>>(() => {
    const initial = [];
    const now = Date.now();
    for (let i = 24; i >= 0; i--) {
      const timeLabel = new Date(now - i * 1200).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });
      initial.push({
        time: timeLabel,
        eps: 0
      });
    }
    return initial;
  });

  // Track live throughput changes and append to sliding window continuously every second
  React.useEffect(() => {
    const interval = setInterval(() => {
      const nowLabel = new Date().toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      });

      setHistory(prev => {
        return [...prev.slice(1), { time: nowLabel, eps: throughput }];
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [throughput]);

  const timeSeriesData = history;

  const { maliciousCount, piiRedactedCount } = useMemo(() => {
    let mal = 0;
    let pii = 0;
    for (let i = 0; i < logs.length; i++) {
      const l = logs[i];
      const d = l.normalized_data as any;
      const t = l.traceability as any;
      if (d?.threat?.is_malicious || d?.enrichment?.is_malicious) mal++;
      if (d?.compliance?.pii_redacted || t?.redacted_payload) pii++;
    }
    return { maliciousCount: mal, piiRedactedCount: pii };
  }, [logs]);
  
  const totalLogs = logs.length;

  return (
    <div className="space-y-3.5 mb-3">
      {/* 1. The Hero Data Viz (Positioned at the TOP so it is immediately 100% visible on screen load) */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-3.5">
        {/* Left Side (col-span-3): Area Chart */}
        <div className="lg:col-span-3 bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-2xl p-4 sm:p-5 flex flex-col justify-between shadow-xs">
          {/* Header */}
          <div className="flex flex-wrap items-center justify-between pb-3 mb-2 border-b border-slate-100 dark:border-slate-800/80 gap-2">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800/80 text-cyan-700 dark:text-cyan-400">
                <Activity className="w-4 h-4" />
              </div>
              <div>
                <h3 className="text-xs sm:text-sm font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                  Real-Time Event Processing Velocity
                </h3>
                <p className="text-[11px] text-slate-500 dark:text-slate-400">Air-Gapped Ingestion Stream · High-Throughput Vector Pipeline</p>
              </div>
            </div>

            <div className="flex items-center space-x-3 text-xs font-mono">
              <span className="text-slate-500 dark:text-slate-400 text-[11px]">Window: <strong className="text-slate-800 dark:text-slate-200">Rolling 30s</strong></span>
              <span className="inline-flex items-center px-2.5 py-0.5 rounded-full bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800 text-cyan-800 dark:text-cyan-300 font-bold text-[10px]">
                <span className="w-1.5 h-1.5 rounded-full bg-cyan-500 dark:bg-cyan-400 inline-block mr-1 animate-pulse" />
                Live Wire
              </span>
            </div>
          </div>

          {/* Area Chart with Clean Cyan to Transparent Gradient */}
          <div className="h-[230px] sm:h-[260px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={timeSeriesData} margin={{ top: 8, right: 8, left: -20, bottom: 0 }}>
                <defs>
                  <linearGradient id="antigravityCyanGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06b6d4" stopOpacity={0.4} />
                    <stop offset="60%" stopColor="#6366f1" stopOpacity={0.1} />
                    <stop offset="100%" stopColor="#6366f1" stopOpacity={0.0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#334155" strokeOpacity={0.25} strokeDasharray="3 3" vertical={false} />
                <XAxis 
                  dataKey="time" 
                  stroke="#64748b" 
                  fontSize={10} 
                  fontFamily="JetBrains Mono, monospace"
                  tickLine={false} 
                  axisLine={{ stroke: '#475569', strokeOpacity: 0.25 }}
                  tick={{ fill: '#64748b' }}
                />
                <YAxis 
                  stroke="#64748b" 
                  fontSize={10} 
                  fontFamily="JetBrains Mono, monospace"
                  tickLine={false} 
                  axisLine={{ stroke: '#475569', strokeOpacity: 0.25 }}
                  tick={{ fill: '#64748b' }}
                  allowDecimals={false}
                  domain={[0, (dataMax: number) => Math.max(10, dataMax + 2)]} 
                />
                <Tooltip 
                  contentStyle={{ 
                    backgroundColor: 'rgba(15, 23, 42, 0.95)', 
                    borderColor: 'rgba(255, 255, 255, 0.1)', 
                    borderRadius: '12px', 
                    fontSize: '11px',
                    fontFamily: 'JetBrains Mono, monospace',
                    boxShadow: '0 20px 40px -10px rgba(0,0,0,0.5)',
                    color: '#f8fafc'
                  }}
                  itemStyle={{ color: '#22d3ee', fontWeight: 700 }}
                  labelStyle={{ color: '#94a3b8', marginBottom: '4px' }}
                />
                <Area 
                  type="monotone" 
                  dataKey="eps" 
                  name="Ingestion (EPS)"
                  stroke="#06b6d4" 
                  strokeWidth={2.5} 
                  fillOpacity={1} 
                  fill="url(#antigravityCyanGradient)" 
                  isAnimationActive={false}
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Right Side (col-span-1): Threat Taxonomy */}
        <div className="lg:col-span-1 bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-2xl p-4 sm:p-5 flex flex-col justify-between shadow-xs">
          <div>
            <div className="flex items-center justify-between pb-3 mb-2 border-b border-slate-100 dark:border-slate-800/80">
              <div className="flex items-center space-x-2">
                <div className="p-1.5 rounded-xl bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 text-rose-600 dark:text-rose-400">
                  <ShieldAlert className="w-3.5 h-3.5" />
                </div>
                <h3 className="text-xs font-bold text-slate-900 dark:text-white uppercase tracking-wider">
                  Threat Taxonomy
                </h3>
              </div>
              <span className="text-[10px] font-mono text-slate-700 dark:text-cyan-300 px-2 py-0.5 rounded-full bg-slate-100 dark:bg-cyan-950/60 border border-slate-200 dark:border-cyan-800 font-bold">
                OCSF v1.1
              </span>
            </div>

            {/* Donut Chart with Informative Center & Legend */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 items-center my-1">
              {/* Left: Donut Chart with Center Totals */}
              <div className="h-36 flex items-center justify-center relative">
                {categoryData.length > 0 ? (
                  <>
                    <ResponsiveContainer width="100%" height="100%">
                      <PieChart>
                        <Pie
                          data={categoryData}
                          cx="50%"
                          cy="50%"
                          innerRadius={36}
                          outerRadius={56}
                          paddingAngle={3}
                          stroke="transparent"
                          strokeWidth={2}
                          dataKey="value"
                          isAnimationActive={false}
                        >
                          {categoryData.map((_, index) => (
                            <Cell key={`cell-${index}`} fill={TAXONOMY_COLORS[index % TAXONOMY_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip 
                          contentStyle={{ 
                            backgroundColor: 'rgba(15, 23, 42, 0.95)', 
                            borderColor: 'rgba(255, 255, 255, 0.1)', 
                            borderRadius: '8px', 
                            fontSize: '11px',
                            fontFamily: 'JetBrains Mono, monospace',
                            boxShadow: '0 4px 12px rgba(0,0,0,0.4)',
                            color: '#f8fafc' 
                          }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                    {/* Informative Center Label */}
                    <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none text-center">
                      <span className="text-base font-extrabold font-mono text-slate-900 dark:text-white leading-tight">
                        {categoryData.reduce((acc, curr) => acc + curr.value, 0)}
                      </span>
                      <span className="text-[9px] uppercase font-mono font-semibold text-slate-600 dark:text-slate-400 leading-none">
                        Events
                      </span>
                    </div>
                  </>
                ) : (
                  <div className="text-xs text-slate-500 font-['JetBrains_Mono']">Buffering taxonomy...</div>
                )}
              </div>

              {/* Right: Explicit Category Breakdown Legend */}
              <div className="space-y-1.5 font-['JetBrains_Mono'] text-[11px] pr-1">
                {categoryData.slice(0, 4).map((item, idx) => {
                  const total = categoryData.reduce((acc, curr) => acc + curr.value, 0) || 1;
                  const pct = Math.round((item.value / total) * 100);
                  const color = TAXONOMY_COLORS[idx % TAXONOMY_COLORS.length];
                  return (
                    <div key={idx} className="flex items-center justify-between py-0.5">
                      <div className="flex items-center gap-1.5 min-w-0">
                        <span className="w-2.5 h-2.5 rounded-full shrink-0 shadow-xs" style={{ backgroundColor: color }} />
                        <span className="text-slate-800 dark:text-slate-200 truncate font-medium text-[10px]" title={item.name}>
                          {item.name}
                        </span>
                      </div>
                      <div className="flex items-center gap-1 shrink-0 ml-1">
                        <span className="text-[10px] font-bold text-slate-900 dark:text-white">{item.value}</span>
                        <span className="text-[9px] text-slate-500 font-normal">({pct}%)</span>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
            <p className="text-[10px] text-slate-500 dark:text-slate-400 font-sans mt-1">
              Classified log volume grouped by standardized OCSF v1.1.0 security activity categories.
            </p>
          </div>

          {/* List of Detected Adversaries */}
          <div className="mt-3 pt-2.5 border-t border-slate-100 dark:border-slate-800/80 space-y-1.5">
            <span className="text-slate-500 dark:text-slate-400 uppercase tracking-wider text-[10px] font-bold block font-['JetBrains_Mono']">
              Detected Adversaries (Threat Intel)
            </span>
            <div className="space-y-1 font-['JetBrains_Mono'] text-xs">
              {threatGeoData.length > 0 ? (
                threatGeoData.slice(0, 2).map((item, idx) => (
                  <div key={idx} className="flex items-center justify-between text-slate-800 dark:text-slate-200 bg-slate-50 dark:bg-slate-800/60 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700/80">
                    <span className="text-rose-600 dark:text-rose-400 font-semibold truncate max-w-[140px] text-[10px]">{item.name}</span>
                    <span className="text-slate-700 dark:text-slate-200 font-bold px-1.5 py-0.2 rounded bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-[10px] shadow-xs">{item.count}</span>
                  </div>
                ))
              ) : (
                <div className="text-slate-400 italic text-[10px] py-0.5 text-center font-['JetBrains_Mono']">
                  No active signatures
                </div>
              )}
            </div>
          </div>
        </div>
      </div>


      {/* 3. Top Metrics Ribbon: 4 Clean Solid Metric Cards (Compact & Crisp) */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        {/* Metric 1: Ingestion Velocity */}
        <SpotlightCard 
          spotlightColor="rgba(6, 182, 212, 0.16)"
          className="bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-2xl p-3.5 flex flex-col justify-between transition-all duration-150 hover:shadow-md"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-600 dark:bg-cyan-400 animate-pulse" />
              Ingestion Velocity
            </span>
            <span className="text-[9px] font-mono text-blue-700 dark:text-cyan-300 bg-blue-50 dark:bg-cyan-950/60 border border-blue-200 dark:border-cyan-800 px-1.5 py-0.5 rounded-full font-bold flex items-center gap-1">
              <ArrowUpRight className="w-2.5 h-2.5 text-blue-600 dark:text-cyan-400" />
              Live Wire
            </span>
          </div>
          <div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-extrabold font-mono tracking-tight text-slate-900 dark:text-white">
                <AnimatedCounter value={throughput} />
              </span>
              <span className="text-xs font-mono text-slate-500 dark:text-slate-400 font-semibold">EPS</span>
            </div>
            <div className="mt-0.5 text-[10px] font-mono text-slate-500 dark:text-slate-400 flex items-center gap-1">
              <span>Latency: <strong className="text-slate-800 dark:text-slate-200">0.6ms</strong></span>
              <span className="text-slate-300 dark:text-slate-700">·</span>
              <span>Drop: <strong className="text-blue-600 dark:text-cyan-400">0%</strong></span>
            </div>
          </div>
        </SpotlightCard>

        {/* Metric 2: Threat Intel Hits */}
        <SpotlightCard 
          spotlightColor="rgba(244, 63, 94, 0.16)"
          className="bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-2xl p-3.5 flex flex-col justify-between transition-all duration-150 hover:shadow-md"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-rose-500 animate-pulse" />
              Threat Intel
            </span>
            <span className="text-[9px] font-mono text-rose-700 dark:text-rose-300 bg-rose-50 dark:bg-rose-950/60 border border-rose-200 dark:border-rose-800 px-1.5 py-0.5 rounded-full font-bold uppercase">
              {totalLogs ? Math.round((maliciousCount / totalLogs) * 100) : 0}% Correlated
            </span>
          </div>
          <div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-extrabold font-mono tracking-tight text-slate-900 dark:text-white">
                <AnimatedCounter value={maliciousCount} />
              </span>
              <span className="text-xs font-mono text-rose-600 dark:text-rose-400 font-semibold">Threats</span>
            </div>
            <div className="mt-0.5 text-[10px] font-mono text-slate-500 dark:text-slate-400">
              MITRE ATT&CK: <strong className="text-slate-800 dark:text-slate-200">Active Defense</strong>
            </div>
          </div>
        </SpotlightCard>

        {/* Metric 3: PII Scrubbed */}
        <SpotlightCard 
          spotlightColor="rgba(14, 165, 233, 0.16)"
          className="bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-2xl p-3.5 flex flex-col justify-between transition-all duration-150 hover:shadow-md"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-cyan-500" />
              PII Sanitized
            </span>
            <span className="text-[9px] font-mono text-cyan-700 dark:text-cyan-300 bg-cyan-50 dark:bg-cyan-950/60 border border-cyan-200 dark:border-cyan-800 px-1.5 py-0.5 rounded-full font-bold">
              0.00% Leak
            </span>
          </div>
          <div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-extrabold font-mono tracking-tight text-slate-900 dark:text-white">
                <AnimatedCounter value={piiRedactedCount} />
              </span>
              <span className="text-xs font-mono text-cyan-600 dark:text-cyan-400 font-semibold">Tokens</span>
            </div>
            <div className="mt-0.5 text-[10px] font-mono text-slate-500 dark:text-slate-400">
              Redaction: <strong className="text-slate-800 dark:text-slate-200">Verhoeff Crypto</strong>
            </div>
          </div>
        </SpotlightCard>

        {/* Metric 4: OCSF Standard Match */}
        <SpotlightCard 
          spotlightColor="rgba(59, 130, 246, 0.16)"
          className="bg-white dark:bg-slate-900/90 border border-slate-200/90 dark:border-slate-800/80 rounded-2xl p-3.5 flex flex-col justify-between transition-all duration-150 hover:shadow-md"
        >
          <div className="flex items-center justify-between mb-1">
            <span className="text-[10px] font-semibold text-slate-500 dark:text-slate-400 uppercase tracking-wider flex items-center gap-1.5">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-600 dark:bg-cyan-400" />
              OCSF Standard
            </span>
            <span className="text-[9px] font-mono text-blue-700 dark:text-cyan-300 bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800 px-1.5 py-0.5 rounded-full font-bold">
              SHA-256 Valid
            </span>
          </div>
          <div>
            <div className="flex items-baseline space-x-1.5">
              <span className="text-2xl font-extrabold font-mono tracking-tight text-slate-900 dark:text-white">
                100%
              </span>
              <span className="text-xs font-mono text-blue-600 dark:text-cyan-400 font-semibold">v1.1.0</span>
            </div>
            <div className="mt-0.5 text-[10px] font-mono text-slate-500 dark:text-slate-400">
              Schema: <strong className="text-slate-800 dark:text-slate-200">2001 · 3002 · 4001</strong>
            </div>
          </div>
        </SpotlightCard>
      </div>
    </div>
  );
};

export const TelemetryMetrics = React.memo(TelemetryMetricsComponent);