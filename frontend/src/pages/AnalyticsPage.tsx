import { useDashboard } from '@/context/DashboardContext';
import { SectionCard, PageHeader, StatCard } from '@/components/StatCard';
import { SkeletonCard } from '@/components/Loaders';
import { Heatmap, MiniGauge } from '@/components/Charts';
import { DETECTORS, SEVERITY_META, SEVERITY_ORDER } from '@/lib/detectors';
import type { DetectorKey } from '@/lib/types';
import {
  PieChart, Pie, Cell, ResponsiveContainer, BarChart, Bar, XAxis, YAxis, Tooltip, CartesianGrid, AreaChart, Area, LineChart, Line, Legend,
} from 'recharts';
import { AlertTriangle, ShieldAlert, Activity, TrendingUp } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { Network, Globe, Wifi, Lock, FileCode2, Route, Server } from 'lucide-react';

const CHART_BG = 'rgba(255,255,255,0.04)';
const AXIS_COLOR = '#64748B';
const TOOLTIP_STYLE = { background: '#161D2A', border: '1px solid #1F2A3C', borderRadius: 8, fontSize: 12 };
const ICONS: Record<string, LucideIcon> = { Network, Globe, Wifi, Lock, FileCode2, Route, Server };

export function AnalyticsPage() {
  const { data, loading } = useDashboard();

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="Attack Analytics" subtitle="Visual breakdown of detected threats" />
        <div className="grid lg:grid-cols-2 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} className="h-72" />)}
        </div>
      </div>
    );
  }

  const stats = data?.statistics;
  const byDetectorData = (stats?.by_detector ?? []).map((s) => ({
    name: DETECTORS[s.detector as DetectorKey]?.short ?? s.detector,
    value: s.count,
    color: DETECTORS[s.detector as DetectorKey]?.color ?? '#3B82F6',
    label: DETECTORS[s.detector as DetectorKey]?.label ?? s.detector,
  }));
  const bySeverityData = SEVERITY_ORDER.map((sev) => ({
    name: SEVERITY_META[sev].label,
    count: stats?.by_severity[sev] ?? 0,
    color: SEVERITY_META[sev].color,
  }));
  const overTimeData = stats?.over_time ?? [];
  const totalAttacks = byDetectorData.reduce((a, b) => a + b.value, 0);
  const criticalCount = stats?.by_severity.critical ?? 0;
  const heatmapData = stats?.heatmap ?? [];
  const topDevices = stats?.top_devices ?? [];
  const weekComparison = stats?.week_comparison ?? [];
  const detectorHealth = stats?.detector_health ?? [];

  return (
    <div className="space-y-5">
      <PageHeader title="Attack Analytics" subtitle="Visual breakdown of detected threats — data from /api/statistics" />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard icon={TrendingUp} label="Total Attacks" value={totalAttacks} color="#3B82F6" />
        <StatCard icon={ShieldAlert} label="Critical" value={criticalCount} color="#EF4444" />
        <StatCard icon={AlertTriangle} label="High" value={stats?.by_severity.high ?? 0} color="#F97316" />
        <StatCard icon={Activity} label="Active Detectors" value={byDetectorData.filter((d) => d.value > 0).length} color="#22C55E" />
      </div>

      <div className="grid lg:grid-cols-2 gap-4">
        {/* Donut: attacks by type */}
        <SectionCard title="Attacks by Type" subtitle="Distribution across all detectors">
          <div className="h-72 flex items-center">
            <div className="w-1/2 h-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={byDetectorData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={55} outerRadius={90} paddingAngle={2}>
                    {byDetectorData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} stroke={CHART_BG} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={TOOLTIP_STYLE}
                    formatter={(v, _n, p) => [`${v} attacks`, (p?.payload as { label?: string })?.label]}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
            <div className="w-1/2 space-y-1.5 pl-4">
              {byDetectorData.map((d) => (
                <div key={d.name} className="flex items-center justify-between text-xs">
                  <span className="flex items-center gap-2 text-ink-300">
                    <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: d.color }} />
                    {d.label}
                  </span>
                  <span className="font-mono font-semibold text-white tabular-nums">{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        </SectionCard>

        {/* Bar: severity distribution */}
        <SectionCard title="Severity Distribution" subtitle="Alerts grouped by severity level">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={bySeverityData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} vertical={false} />
                <XAxis dataKey="name" tick={{ fill: AXIS_COLOR, fontSize: 11 }} axisLine={{ stroke: CHART_BG }} tickLine={false} />
                <YAxis tick={{ fill: AXIS_COLOR, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {bySeverityData.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </SectionCard>
      </div>

      {/* Area: attacks over time */}
      <SectionCard title="Attacks Over Time" subtitle="Hourly trend of detected attacks (last 24 hours)">
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={overTimeData} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
              <defs>
                <linearGradient id="attackGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                  <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} vertical={false} />
              <XAxis dataKey="time" tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={{ stroke: CHART_BG }} tickLine={false} interval={3} />
              <YAxis tick={{ fill: AXIS_COLOR, fontSize: 11 }} axisLine={false} tickLine={false} allowDecimals={false} />
              <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94A3B8' }} />
              <Area type="monotone" dataKey="count" stroke="#3B82F6" strokeWidth={2} fill="url(#attackGradient)" />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </SectionCard>

      {/* NEW: Heatmap */}
      <SectionCard title="Attack Heatmap" subtitle="Attacks by hour of day vs. day of week — darker means more attacks">
        {heatmapData.length === 0 ? (
          <div className="h-48 flex items-center justify-center text-xs text-ink-500">No heatmap data available</div>
        ) : (
          <Heatmap data={heatmapData} />
        )}
      </SectionCard>

      <div className="grid lg:grid-cols-2 gap-4">
        {/* NEW: Top targeted devices */}
        <SectionCard title="Top Targeted Devices" subtitle="Devices involved in the most alerts">
          {topDevices.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-ink-500">No device data available</div>
          ) : (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={topDevices} layout="vertical" margin={{ top: 5, right: 10, left: 20, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} horizontal={false} />
                  <XAxis type="number" tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <YAxis type="category" dataKey="hostname" tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={false} tickLine={false} width={90} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} formatter={(v, _n, p) => [`${v} alerts`, (p?.payload as { ip?: string })?.ip ?? '']} />
                  <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                    {topDevices.map((d, i) => (
                      <Cell key={i} fill={d.suspicious ? '#EF4444' : '#3B82F6'} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </SectionCard>

        {/* NEW: Week-over-week comparison */}
        <SectionCard title="Week-over-Week Comparison" subtitle="This week vs. last week attack volume">
          {weekComparison.length === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-ink-500">No comparison data available</div>
          ) : (
            <div className="h-72">
              <ResponsiveContainer width="100%" height="100%">
                <LineChart data={weekComparison} margin={{ top: 10, right: 10, left: -10, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} vertical={false} />
                  <XAxis dataKey="day" tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={{ stroke: CHART_BG }} tickLine={false} />
                  <YAxis tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94A3B8' }} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  <Line type="monotone" dataKey="thisWeek" stroke="#3B82F6" strokeWidth={2} dot={{ r: 3 }} name="This Week" />
                  <Line type="monotone" dataKey="lastWeek" stroke="#64748B" strokeWidth={2} strokeDasharray="5 5" dot={{ r: 3 }} name="Last Week" />
                </LineChart>
              </ResponsiveContainer>
            </div>
          )}
        </SectionCard>
      </div>

      {/* NEW: Detector health radials */}
      <SectionCard title="Detector Health" subtitle="Uptime and detections today per detector">
        {detectorHealth.length === 0 ? (
          <div className="h-32 flex items-center justify-center text-xs text-ink-500">No detector health data available</div>
        ) : (
          <div className="grid grid-cols-2 sm:grid-cols-4 lg:grid-cols-7 gap-4">
            {detectorHealth.map((dh) => {
              const meta = DETECTORS[dh.detector as DetectorKey];
              const Icon = ICONS[meta?.icon ?? 'Wifi'] ?? Wifi;
              return (
                <div key={dh.detector} className="card-panel p-3 flex flex-col items-center text-center">
                  <div className="w-8 h-8 rounded-lg flex items-center justify-center mb-1" style={{ backgroundColor: `${meta?.color}18`, color: meta?.color }}>
                    <Icon className="w-4 h-4" />
                  </div>
                  <div className="text-[10px] font-semibold text-ink-300 mb-1">{meta?.short ?? dh.detector}</div>
                  <MiniGauge value={dh.uptime} max={100} color={dh.uptime > 97 ? '#22C55E' : dh.uptime > 94 ? '#F59E0B' : '#EF4444'} size={80} />
                  <div className="text-[10px] text-ink-500 mt-1">{dh.detections_today} today</div>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>
    </div>
  );
}
