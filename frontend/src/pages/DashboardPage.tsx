import { useDashboard } from '@/context/DashboardContext';
import { HealthIndicator } from '@/components/HealthIndicator';
import { StatCard, PageHeader, SectionCard } from '@/components/StatCard';
import { AlertCard } from '@/components/AlertCard';
import { SkeletonCard, SkeletonList, EmptyState, ErrorState } from '@/components/Loaders';
import { Sparkline, InfoIcon } from '@/components/Charts';
import { DETECTORS, SEVERITY_META, SEVERITY_ORDER } from '@/lib/detectors';
import type { DetectorKey, Severity } from '@/lib/types';
import { formatCompact, relativeTime } from '@/lib/format';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';
import {
  Shield, Activity, AlertTriangle, Wifi, Network, Globe, Lock, FileCode2, Route, Server, Zap, Cpu,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

const ICONS: Record<string, LucideIcon> = { Network, Globe, Wifi, Lock, FileCode2, Route, Server };

function calcTrendPct(current: number, previous: number): { pct: number; dir: 'up' | 'down' } | undefined {
  if (previous === 0) return undefined;
  const diff = Math.round(((current - previous) / previous) * 100);
  if (diff === 0) return undefined;
  return { pct: Math.abs(diff), dir: diff > 0 ? 'up' : 'down' };
}

export function DashboardPage() {
  const { data, loading, online, refresh, health } = useDashboard();

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="Network Overview" subtitle="Real-time security posture of your network" />
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-5">
          {Array.from({ length: 4 }).map((_, i) => <SkeletonCard key={i} />)}
        </div>
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2"><SkeletonList count={5} /></div>
          <SkeletonCard />
        </div>
      </div>
    );
  }

  if (!online && !data) {
    return <ErrorState message="Check that the monitoring service is running on the configured backend URL." onRetry={refresh} />;
  }

  const alerts = data?.alerts ?? [];
  const activeAlerts = alerts.length;
  const critical = alerts.filter((a) => a.details.severity === 'critical').length;
  const high = alerts.filter((a) => a.details.severity === 'high').length;
  const packetRate = data?.network.packet_rate ?? 0;
  const deviceCount = data?.network.devices.length ?? 0;
  const monitoring = data?.status.monitoring ?? false;
  const packetHistory = data?.packetHistory ?? [];
  const trends = data?.trends;

  const alertsTrend = trends ? calcTrendPct(activeAlerts, trends.activeAlerts) : undefined;
  const packetTrend = trends ? calcTrendPct(packetRate, trends.packetRate) : undefined;
  const criticalTrend = trends ? calcTrendPct(critical, trends.critical) : undefined;

  const severityData = SEVERITY_ORDER.map((sev) => ({
    name: SEVERITY_META[sev].label,
    value: alerts.filter((a) => a.details.severity === sev).length,
    color: SEVERITY_META[sev].color,
  }));
  const totalSeverity = severityData.reduce((a, b) => a + b.value, 0);

  return (
    <div className="space-y-5">
      <PageHeader title="Network Overview" subtitle="Real-time security posture of your network" />

      {/* Onboarding / first-time guide */}
      {health === 'monitoring_off' && (
        <div className="card p-4 border-blue-500/30 bg-blue-500/5">
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-500/20 flex items-center justify-center flex-shrink-0">
              <Shield className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <h3 className="text-sm font-semibold text-white">Welcome to ShadowPulse</h3>
              <p className="text-xs text-ink-300 mt-1 leading-relaxed">
                ShadowPulse watches your network for attacks like Wi-Fi impersonation, traffic interception, and tampering —
                and explains each threat in plain language so you know what to do. Turn on monitoring to start scanning, or
                visit Settings to pick your network interface.
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Hero status + key stats */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="card p-5 flex flex-col justify-between lg:row-span-1">
          <HealthIndicator size="lg" />
          <div className="mt-4 text-xs text-ink-400 leading-relaxed">
            {health === 'secure' && 'No active threats detected. All detectors are reporting normally.'}
            {health === 'monitoring' && 'Suspicious anomalies detected. Monitoring closely — no confirmed attack yet.'}
            {health === 'under_attack' && `${critical + high} active critical/high alerts require attention.`}
            {health === 'monitoring_off' && 'Monitoring is currently off. Start it to scan for threats.'}
            {health === 'offline' && 'Cannot reach the backend service.'}
          </div>
        </div>

        <StatCard
          icon={AlertTriangle}
          label="Active Alerts"
          value={activeAlerts}
          sub={`${critical} critical · ${high} high`}
          color="#EF4444"
          trend={alertsTrend?.dir}
          trendPct={alertsTrend?.pct}
        />
        <StatCard
          icon={Activity}
          label="Packet Rate"
          value={`${formatCompact(packetRate)}/s`}
          sub={`${formatCompact(data?.network.packet_count ?? 0)} total`}
          color="#3B82F6"
          trend={packetTrend?.dir}
          trendPct={packetTrend?.pct}
        >
          {packetHistory.length > 1 && (
            <div className="opacity-80">
              <Sparkline data={packetHistory} color="#3B82F6" height={36} width={90} />
            </div>
          )}
        </StatCard>
      </div>

      {/* Detector quick stats — only shown while monitoring is active */}
      {monitoring && (
        <SectionCard title="Detector Status" subtitle="Quick view of each attack detector">
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-7 gap-3">
            {(Object.keys(DETECTORS) as DetectorKey[]).map((key) => {
              const meta = DETECTORS[key];
              const stat = data?.statistics.by_detector.find((s) => s.detector === key);
              const enabled = data?.status.detectors_enabled[key] ?? true;
              const Icon = ICONS[meta.icon] ?? Wifi;
              const count = stat?.count ?? 0;
              return (
                <div key={key} className="card-panel p-3 text-center hover:border-soc-hover transition-all">
                  <div
                    className="w-9 h-9 rounded-lg mx-auto flex items-center justify-center mb-2"
                    style={{ backgroundColor: `${meta.color}18`, color: meta.color, opacity: enabled ? 1 : 0.4 }}
                  >
                    <Icon className="w-4.5 h-4.5" style={{ width: 18, height: 18 }} />
                  </div>
                  <div className="text-xs font-semibold text-white">{meta.short}</div>
                  <div className="text-lg font-bold tabular-nums" style={{ color: count > 0 ? meta.color : '#64748B' }}>
                    {count}
                  </div>
                  <div className="flex items-center justify-center gap-1 mt-1">
                    <span className={`w-1.5 h-1.5 rounded-full ${enabled ? 'bg-green-400' : 'bg-ink-600'}`} />
                    <span className="text-[10px] text-ink-500">{enabled ? 'On' : 'Off'}</span>
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>
      )}


      {/* Recent alerts + Severity donut */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="lg:col-span-2">
          <SectionCard title="Recent Alerts" subtitle="Latest threats detected on your network">
            {alerts.length === 0 ? (
              <EmptyState icon={Shield} title="No threats detected" message="Your network is secure. ShadowPulse will show threats here as they are detected." />
            ) : (
              <div className="space-y-2 max-h-[500px] overflow-y-auto pr-1">
                {alerts.slice(0, 10).map((a) => (
                  <div key={a.id} className="card p-3.5 transition-all hover:border-soc-hover" style={{ borderLeftWidth: '3px', borderLeftColor: SEVERITY_META[a.details.severity].color }}>
                    <div className="flex items-start gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-sm font-semibold text-white">{DETECTORS[a.detector].label}</span>
                          <InfoIcon text={DETECTORS[a.detector].plainEnglish} />
                        </div>
                        <p className="text-xs text-ink-400 mt-1">{a.details.description ?? a.alert_type}</p>
                      </div>
                      <span className="text-[11px] text-ink-500 font-mono whitespace-nowrap">{relativeTime(a.timestamp)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </SectionCard>
        </div>
        <SectionCard title="Severity Breakdown" subtitle="Alerts by severity level">
          {totalSeverity === 0 ? (
            <div className="h-48 flex items-center justify-center text-xs text-ink-500">No alerts to display</div>
          ) : (
            <>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={severityData} dataKey="value" nameKey="name" cx="50%" cy="50%" innerRadius={45} outerRadius={75} paddingAngle={2}>
                      {severityData.map((entry, i) => (
                        <Cell key={i} fill={entry.color} stroke="rgba(255,255,255,0.04)" />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ background: '#161D2A', border: '1px solid #1F2A3C', borderRadius: 8, fontSize: 12 }}
                      formatter={(v) => [`${v} alerts`, '']}
                    />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="space-y-1.5 mt-2">
                {severityData.map((s) => (
                  <div key={s.name} className="flex items-center justify-between text-xs">
                    <span className="flex items-center gap-2 text-ink-300">
                      <span className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: s.color }} />
                      {s.name}
                    </span>
                    <span className="font-mono font-semibold text-white tabular-nums">{s.value}</span>
                  </div>
                ))}
              </div>
            </>
          )}
          <div className="mt-4 pt-3 border-t border-soc-border text-xs text-ink-500">
            Last updated {data ? relativeTime(new Date(data.lastUpdated).toISOString()) : '—'}
          </div>
        </SectionCard>
      </div>
    </div>
  );
}
