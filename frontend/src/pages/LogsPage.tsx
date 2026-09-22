import { useState, useMemo } from 'react';
import { useDashboard } from '@/context/DashboardContext';
import { PageHeader, SectionCard } from '@/components/StatCard';
import { SkeletonTable, EmptyState } from '@/components/Loaders';
import { SeverityBadge } from '@/components/SeverityBadge';
import { DETECTORS, SEVERITY_META, SEVERITY_ORDER } from '@/lib/detectors';
import type { DetectorKey, Severity } from '@/lib/types';
import { formatDate } from '@/lib/format';
import { Search, Download, ScrollText } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts';

const CHART_BG = 'rgba(255,255,255,0.04)';
const AXIS_COLOR = '#64748B';
const TOOLTIP_STYLE = { background: '#161D2A', border: '1px solid #1F2A3C', borderRadius: 8, fontSize: 12 };

export function LogsPage() {
  const { data, loading } = useDashboard();
  const [query, setQuery] = useState('');
  const [detectorFilter, setDetectorFilter] = useState<'all' | DetectorKey>('all');
  const [severityFilter, setSeverityFilter] = useState<'all' | Severity>('all');

  const logs = data?.logs ?? [];

  const filtered = useMemo(() => {
    return logs.filter((l) => {
      if (detectorFilter !== 'all' && l.detector !== detectorFilter) return false;
      if (severityFilter !== 'all' && l.severity !== severityFilter) return false;
      if (query) {
        const q = query.toLowerCase();
        return (
          l.message.toLowerCase().includes(q) ||
          l.alert_type.toLowerCase().includes(q) ||
          DETECTORS[l.detector].label.toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [logs, query, detectorFilter, severityFilter]);

  function exportData(format: 'json' | 'csv') {
    const rows = filtered;
    let content: string;
    let mime: string;
    if (format === 'json') {
      content = JSON.stringify(rows, null, 2);
      mime = 'application/json';
    } else {
      const header = 'id,timestamp,detector,alert_type,severity,message';
      const body = rows.map((r) =>
        [r.id, r.timestamp, r.detector, r.alert_type, r.severity, '"' + r.message.replace(/"/g, '""') + '"'].join(',')
      ).join('\n');
      content = `${header}\n${body}`;
      mime = 'text/csv';
    }
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `shadowpulse-logs.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  }

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="Alert Logs" subtitle="Searchable history of all detected alerts" />
        <SkeletonTable rows={8} cols={5} />
      </div>
    );
  }

  return (
    <div className="space-y-5">
      <PageHeader
        title="Alert Logs"
        subtitle="Searchable, filterable history of all detected alerts — data from /api/logs"
        action={
          <div className="flex gap-2">
            <button onClick={() => exportData('json')} className="btn-outline text-xs">
              <Download className="w-3.5 h-3.5" /> JSON
            </button>
            <button onClick={() => exportData('csv')} className="btn-outline text-xs">
              <Download className="w-3.5 h-3.5" /> CSV
            </button>
          </div>
        }
      />

      {/* Filters */}
      <div className="card p-3 flex flex-col md:flex-row gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-ink-500" />
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search alerts by type, message, or detector..."
            className="input pl-9"
          />
        </div>
        <select
          value={detectorFilter}
          onChange={(e) => setDetectorFilter(e.target.value as 'all' | DetectorKey)}
          className="input md:w-48"
        >
          <option value="all">All Detectors</option>
          {(Object.keys(DETECTORS) as DetectorKey[]).map((k) => (
            <option key={k} value={k}>{DETECTORS[k].label}</option>
          ))}
        </select>
        <select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value as 'all' | Severity)}
          className="input md:w-40"
        >
          <option value="all">All Severities</option>
          {SEVERITY_ORDER.map((s) => (
            <option key={s} value={s}>{SEVERITY_META[s].label}</option>
          ))}
        </select>
      </div>

      {/* Results count */}
      <div className="text-xs text-ink-500">
        Showing {filtered.length} of {logs.length} log entries
      </div>

      {/* 7-day alert volume chart */}
      <SectionCard title="7-Day Alert Volume" subtitle="Daily alert count trend — spot patterns before scrolling through raw entries">
        <div className="h-40">
          {data?.statistics.daily_volume && data.statistics.daily_volume.length > 0 ? (
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.statistics.daily_volume} margin={{ top: 5, right: 10, left: -15, bottom: 0 }}>
                <CartesianGrid strokeDasharray="3 3" stroke={CHART_BG} vertical={false} />
                <XAxis dataKey="day" tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={{ stroke: CHART_BG }} tickLine={false} />
                <YAxis tick={{ fill: AXIS_COLOR, fontSize: 10 }} axisLine={false} tickLine={false} allowDecimals={false} />
                <Tooltip contentStyle={TOOLTIP_STYLE} cursor={{ fill: 'rgba(255,255,255,0.04)' }} formatter={(v) => [`${v} alerts`, '']} />
                <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                  {data.statistics.daily_volume.map((d, i) => (
                    <Cell key={i} fill={d.count > 10 ? '#EF4444' : d.count > 5 ? '#F97316' : '#3B82F6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          ) : (
            <div className="h-full flex items-center justify-center text-xs text-ink-500">No volume data available</div>
          )}
        </div>
      </SectionCard>

      {/* Table */}
      {filtered.length === 0 ? (
        <EmptyState icon={ScrollText} title="No matching logs" message="No log entries match your filters. Try adjusting your search or filters." />
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table className="w-full text-sm">
              <thead className="sticky top-0 bg-soc-card z-10">
                <tr className="border-b border-soc-border text-xs text-ink-400 uppercase tracking-wide">
                  <th className="text-left p-3 font-medium">Timestamp</th>
                  <th className="text-left p-3 font-medium">Detector</th>
                  <th className="text-left p-3 font-medium">Alert Type</th>
                  <th className="text-left p-3 font-medium">Severity</th>
                  <th className="text-left p-3 font-medium">Message</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {filtered.map((l) => {
                  const meta = DETECTORS[l.detector];
                  return (
                    <tr key={l.id} className="hover:bg-soc-hover">
                      <td className="p-3 font-mono text-xs text-ink-400 whitespace-nowrap">{formatDate(l.timestamp)}</td>
                      <td className="p-3">
                        <span className="flex items-center gap-1.5 text-xs">
                          <span className="w-2 h-2 rounded-full" style={{ backgroundColor: meta.color }} />
                          <span className="text-ink-200">{meta.label}</span>
                        </span>
                      </td>
                      <td className="p-3 font-mono text-xs text-ink-300">{l.alert_type}</td>
                      <td className="p-3"><SeverityBadge severity={l.severity} size="xs" /></td>
                      <td className="p-3 text-xs text-ink-300">{l.message}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
