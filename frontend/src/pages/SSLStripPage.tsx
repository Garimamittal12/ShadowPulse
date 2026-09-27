import { useDashboard } from '@/context/DashboardContext';
import { PageHeader, SectionCard } from '@/components/StatCard';
import { SkeletonList, EmptyState } from '@/components/Loaders';
import { SeverityBadge } from '@/components/SeverityBadge';
import { GaugeChart } from '@/components/Charts';
import type { SSLSession } from '@/lib/types';
import { Lock, Unlock, ShieldCheck, ShieldAlert, ArrowRightCircle, Info } from 'lucide-react';

const STATUS_META: Record<SSLSession['status'], { label: string; color: string; icon: typeof Lock }> = {
  secure: { label: 'Secure', color: '#22C55E', icon: ShieldCheck },
  downgraded: { label: 'Downgraded', color: '#F59E0B', icon: ArrowRightCircle },
  stripped: { label: 'SSL Stripped', color: '#EF4444', icon: ShieldAlert },
  redirect: { label: 'Redirect', color: '#F97316', icon: ArrowRightCircle },
};

function calcSecurityScore(sessions: SSLSession[]): number {
  if (sessions.length === 0) return 100;
  const secure = sessions.filter((s) => s.status === 'secure' && s.has_hsts).length;
  const stripped = sessions.filter((s) => s.status === 'stripped').length;
  const downgraded = sessions.filter((s) => s.status === 'downgraded' || s.status === 'redirect').length;
  const score = (secure / sessions.length) * 100 - (stripped * 15 + downgraded * 5);
  return Math.max(0, Math.min(100, Math.round(score)));
}

function scoreLabel(score: number): { label: string; color: string } {
  if (score >= 80) return { label: 'Good', color: '#22C55E' };
  if (score >= 50) return { label: 'Needs Attention', color: '#F59E0B' };
  return { label: 'At Risk', color: '#EF4444' };
}

export function SSLStripPage() {
  const { data, loading } = useDashboard();

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="SSL Strip Monitor" subtitle="HTTPS session integrity monitoring" />
        <SkeletonList count={4} />
      </div>
    );
  }

  const ssl = data?.sslStrip;
  const sessions = ssl?.sessions ?? [];
  const warnings = ssl?.warnings ?? [];
  const secureCount = sessions.filter((s) => s.status === 'secure').length;
  const atRiskCount = sessions.length - secureCount;
  const securityScore = calcSecurityScore(sessions);
  const sl = scoreLabel(securityScore);

  return (
    <div className="space-y-5">
      <PageHeader title="SSL Strip Monitor" subtitle="Detects HTTPS downgrades, SSL stripping, and missing HSTS — data from /api/ssl" />

      {/* HTTPS Security Score gauge + stats */}
      <div className="grid lg:grid-cols-3 gap-4">
        <div className="card p-5 flex flex-col items-center justify-center">
          <div className="text-xs text-ink-400 uppercase tracking-wide font-medium mb-2">HTTPS Security Score</div>
          <GaugeChart value={securityScore} max={100} color={sl.color} size={200} label={sl.label} sublabel={`${secureCount}/${sessions.length} sessions secure`} />
        </div>
        <div className="lg:col-span-2 grid grid-cols-2 md:grid-cols-3 gap-4">
          <div className="card p-4">
            <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><ShieldCheck className="w-4 h-4 text-green-400" /> Secure Sessions</div>
            <div className="text-2xl font-bold text-green-400">{secureCount}</div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><ShieldAlert className="w-4 h-4 text-red-400" /> At-Risk Sessions</div>
            <div className="text-2xl font-bold text-red-400">{atRiskCount}</div>
          </div>
          <div className="card p-4">
            <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><Lock className="w-4 h-4 text-amber-400" /> Active Warnings</div>
            <div className="text-2xl font-bold text-amber-400">{warnings.length}</div>
          </div>
        </div>
      </div>

      {/* Plain-language explainer */}
      <div className="card p-4 border-blue-500/20 bg-blue-500/5">
        <div className="flex items-start gap-3">
          <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-xs text-ink-300 leading-relaxed">
            <span className="font-semibold text-blue-300">What is SSL Stripping? </span>
            When you visit a secure website, your browser should use HTTPS (encrypted). SSL stripping silently downgrades
            the connection to unencrypted HTTP — <span className="text-amber-300">meaning someone may be able to read your "secure" traffic</span>,
            including passwords and banking details. Look for the lock icon in your browser, and avoid entering sensitive
            information on sites flagged below.
          </div>
        </div>
      </div>

      {/* Warnings */}
      {warnings.length > 0 && (
        <SectionCard title="Active Warnings" subtitle="Sessions that require attention">
          <div className="space-y-2">
            {warnings.map((w, i) => (
              <div key={i} className="card-panel p-3 flex items-center gap-3 border-amber-500/20">
                <ShieldAlert className="w-5 h-5 text-amber-400 flex-shrink-0" />
                <div className="flex-1">
                  <div className="text-sm font-semibold text-white">{w.host}</div>
                  <div className="text-xs text-ink-400">{w.message}</div>
                </div>
                <SeverityBadge severity={w.severity} size="xs" />
              </div>
            ))}
          </div>
        </SectionCard>
      )}

      {/* Sessions */}
      <SectionCard title="HTTPS Sessions" subtitle="All monitored secure connections">
        {sessions.length === 0 ? (
          <EmptyState icon={Lock} title="No sessions monitored" message="No HTTPS sessions detected yet. Sessions will appear here as traffic is monitored." />
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-soc-border text-xs text-ink-400 uppercase tracking-wide">
                  <th className="text-left p-3 font-medium">Host</th>
                  <th className="text-left p-3 font-medium">IP Address</th>
                  <th className="text-left p-3 font-medium">Status</th>
                  <th className="text-left p-3 font-medium">HSTS</th>
                  <th className="text-left p-3 font-medium">Details</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {sessions.map((s: SSLSession) => {
                  const meta = STATUS_META[s.status];
                  const Icon = meta.icon;
                  return (
                    <tr key={s.id} className="hover:bg-soc-hover">
                      <td className="p-3 font-mono text-ink-200">{s.host}</td>
                      <td className="p-3 font-mono text-ink-500 text-xs">{s.ip}</td>
                      <td className="p-3">
                        <span className="flex items-center gap-1.5 text-xs font-semibold" style={{ color: meta.color }}>
                          <Icon className="w-3.5 h-3.5" /> {meta.label}
                        </span>
                      </td>
                      <td className="p-3">
                        {s.has_hsts ? (
                          <span className="flex items-center gap-1 text-xs text-green-400"><Lock className="w-3 h-3" /> Enabled</span>
                        ) : (
                          <span className="flex items-center gap-1 text-xs text-red-400"><Unlock className="w-3 h-3" /> Missing</span>
                        )}
                      </td>
                      <td className="p-3 text-xs text-ink-400">{s.details ?? '—'}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </SectionCard>
    </div>
  );
}
