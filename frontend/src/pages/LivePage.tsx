import { useDashboard } from '@/context/DashboardContext';
import { HealthIndicator } from '@/components/HealthIndicator';
import { AlertCard } from '@/components/AlertCard';
import { SectionCard, StatCard, PageHeader } from '@/components/StatCard';
import { SkeletonList, EmptyState } from '@/components/Loaders';
import { InfoIcon } from '@/components/Charts';
import { DETECTORS, SEVERITY_META, SEVERITY_ORDER } from '@/lib/detectors';
import type { DetectorKey, Alert, Severity } from '@/lib/types';
import { formatCompact, relativeTime, formatTime } from '@/lib/format';
import { Activity, Zap, Radio, Waves, Gauge } from 'lucide-react';
import { useEffect, useRef, useState } from 'react';
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const CHART_BG = 'rgba(255,255,255,0.04)';
const AXIS_COLOR = '#64748B';
const TOOLTIP_STYLE = { background: '#161D2A', border: '1px solid #1F2A3C', borderRadius: 8, fontSize: 12 };

export function LivePage() {
  const { data, loading, health } = useDashboard();
  const feedRef = useRef<HTMLDivElement>(null);
  const prevAlertCount = useRef(0);
  const [packetHistory, setPacketHistory] = useState<{ t: string; rate: number }[]>([]);
  const [severityHistory, setSeverityHistory] = useState<{ t: string; critical: number; high: number; medium: number; low: number; info: number }[]>([]);

  const alerts = data?.alerts ?? [];
  const monitoring = data?.status.monitoring ?? false;

  useEffect(() => {
    if (alerts.length > prevAlertCount.current && feedRef.current) {
      feedRef.current.scrollTop = 0;
    }
    prevAlertCount.current = alerts.length;
  }, [alerts.length]);

  // Update packet history every time data refreshes
  useEffect(() => {
    if (!data) return;
    const t = formatTime(new Date().toISOString());
    const rate = data.network.packet_rate;
    setPacketHistory((prev) => [...prev, { t, rate }].slice(-20));

    const sevCounts = SEVERITY_ORDER.reduce((acc, s: Severity) => {
      acc[s] = alerts.filter((a) => a.details.severity === s).length;
      return acc;
    }, {} as Record<Severity, number>);
    setSeverityHistory((prev) => [...prev, { t, ...sevCounts }].slice(-20));
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [data?.lastUpdated]);

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="Live Monitoring" subtitle="Real-time packet and threat feed" />
        <div className="grid lg:grid-cols-3 gap-4">
          <div className="lg:col-span-2"><SkeletonList count={6} /></div>
        </div>
      </div>
    );
  }

  const packetRate = data?.network.packet_rate ?? 0;
  const packetCount = data?.network.packet_count ?? 0;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Live Monitoring"
        subtitle="Real-time packet and threat feed — alert updates arrive over WebSocket"
        action={<HealthIndicator size="sm" />}
      />

      {/* Live counters */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="card p-4 relative overflow-hidden">
          <div className="flex items-center gap-2 text-xs text-ink-400 mb-2">
            <Activity className={`w-4 h-4 ${monitoring ? 'text-blue-400 animate-pulse-soft' : 'text-ink-500'}`} />
            Live Packet Rate
          </div>
          <div className="text-3xl font-bold text-white tabular-nums">
            {monitoring ? formatCompact(packetRate) : '—'}
            <span className="text-sm text-ink-500 font-normal ml-1">pkt/s</span>
          </div>
          {monitoring && (
            <div className="absolute bottom-0 left-0 right-0 h-1 bg-gradient-to-r from-blue-500/0 via-blue-500/60 to-blue-500/0 animate-ticker" style={{ animationDuration: '2s' }} />
          )}
        </div>
        <StatCard icon={Waves} label="Total Packets" value={formatCompact(packetCount)} color="#3B82F6" />
        <StatCard icon={Zap} label="Active Alerts" value={alerts.length} color="#EF4444" />
        <StatCard icon={Gauge} label="Detectors Active" value={`${Object.values(data?.status.detectors_enabled ?? {}).filter(Boolean).length}/${Object.keys(DETECTORS).length}`} color="#22C55E" />
      </div>

      {/* Real-time packet rate chart */}
      <SectionCard title="Live Packet Rate" subtitle="Last 60 seconds of network activity (pkt/s)" action={monitoring ? (
        <span className="flex items-center gap-1.5 text-xs text-green-400 font-medium">
          <span className="live-dot text-green-400" /> LIVE
        </span>
      ) : <span className="text-xs text-ink-500">Paused</span>}>
        <div className="h-56">
          {packetHistory.length === 0 ? (
            <div className="h-full flex items-center justify-center text-xs text-ink-500">Waiting for data...</div>
          ) : (
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={packetHistory} margin={{ top: 5, right: 10, left: -10, bottom: 0 }}>
                <defs>
                  <linearGradient id="livePacketGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.4} />
                    <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} vertical={false} />
                <XAxis dataKey="t" tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={{ stroke: CHART_BG }} tickLine={false} interval="preserveStartEnd" minTickGap={30} />
                <YAxis tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94A3B8' }} formatter={(v) => [`${v} pkt/s`, '']} />
                <Area type="monotone" dataKey="rate" stroke="#3B82F6" strokeWidth={2} fill="url(#livePacketGrad)" isAnimationActive={false} />
              </AreaChart>
            </ResponsiveContainer>
          )}
        </div>
      </SectionCard>

      <div className="grid lg:grid-cols-3 gap-4">
        {/* Live feed */}
        <div className="lg:col-span-2">
          <SectionCard
            title="Live Threat Feed"
            subtitle="Newest alerts appear at the top automatically"
            action={monitoring ? (
              <span className="flex items-center gap-1.5 text-xs text-green-400 font-medium">
                <span className="live-dot text-green-400" /> LIVE
              </span>
            ) : (
              <span className="text-xs text-ink-500">Paused</span>
            )}
          >
            {!monitoring && alerts.length === 0 ? (
              <EmptyState icon={Radio} title="Monitoring is off" message="Start monitoring from Settings or the top bar to see live threats appear here." />
            ) : alerts.length === 0 ? (
              <EmptyState icon={Radio} title="No threats detected" message="Your network is secure. Live alerts will stream here as they are detected." />
            ) : (
              <div ref={feedRef} className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                {alerts.map((a: Alert) => (
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

        {/* Active detectors + stacked severity + timeline */}
        <div className="contents">
          <SectionCard title="Active Detectors" subtitle="Per-detector monitoring status">
            <div className="space-y-2">
              {(Object.keys(DETECTORS) as DetectorKey[]).map((key) => {
                const meta = DETECTORS[key];
                const enabled = data?.status.detectors_enabled[key] ?? true;
                const count = data?.statistics.by_detector.find((s) => s.detector === key)?.count ?? 0;
                return (
                  <div key={key} className="flex items-center justify-between p-2 rounded-lg hover:bg-soc-hover">
                    <div className="flex items-center gap-2">
                      <span className="w-2 h-2 rounded-full" style={{ backgroundColor: enabled ? meta.color : '#475569' }} />
                      <span className="text-xs font-medium text-ink-200">{meta.label}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      {count > 0 && <span className="text-xs font-mono" style={{ color: meta.color }}>{count}</span>}
                      <span className={`text-[10px] font-semibold ${enabled ? 'text-green-400' : 'text-ink-500'}`}>
                        {enabled ? 'ON' : 'OFF'}
                      </span>
                    </div>
                  </div>
                );
              })}
            </div>
          </SectionCard>

          <div className="lg:col-span-2 grid grid-cols-1 sm:grid-cols-2 gap-4 items-start">
          <SectionCard title="Alerts by Severity" subtitle="Recent severity trend">
            <div className="h-48">
              {severityHistory.length === 0 ? (
                <div className="h-full flex items-center justify-center text-xs text-ink-500">Waiting for data...</div>
              ) : (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={severityHistory} margin={{ top: 5, right: 5, left: -15, bottom: 0 }}>
                    <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} vertical={false} />
                    <XAxis dataKey="t" tick={{ fill: AXIS_COLOR, fontSize: 9 }} axisLine={{ stroke: CHART_BG }} tickLine={false} interval="preserveStartEnd" minTickGap={25} />
                    <YAxis tick={{ fill: AXIS_COLOR, fontSize: 9 }} axisLine={false} tickLine={false} />
                    <Tooltip contentStyle={TOOLTIP_STYLE} labelStyle={{ color: '#94A3B8' }} />
                    {SEVERITY_ORDER.map((sev) => (
                      <Area key={sev} type="monotone" dataKey={sev} stackId="1" stroke={SEVERITY_META[sev].color} fill={SEVERITY_META[sev].color} fillOpacity={0.5} isAnimationActive={false} />
                    ))}
                  </AreaChart>
                </ResponsiveContainer>
              )}
            </div>
          </SectionCard>

          <SectionCard title="Event Timeline" subtitle="Recent alerts">
            <div className="relative pl-4 max-h-48 overflow-y-auto">
              <div className="absolute left-1.5 top-0 bottom-0 w-px bg-soc-border" />
              {alerts.slice(0, 8).map((a) => (
                <div key={a.id} className="relative pb-3">
                  <span
                    className="absolute -left-3 top-1 w-2.5 h-2.5 rounded-full border-2 border-soc-card"
                    style={{ backgroundColor: DETECTORS[a.detector].color }}
                  />
                  <div className="text-xs text-white font-medium">{DETECTORS[a.detector].label}</div>
                  <div className="text-[11px] text-ink-500">{formatTime(a.timestamp)} · {relativeTime(a.timestamp)}</div>
                </div>
              ))}
              {alerts.length === 0 && <div className="text-xs text-ink-500 py-4">No events yet.</div>}
            </div>
          </SectionCard>
          </div>
        </div>
      </div>
    </div>
  );
}
