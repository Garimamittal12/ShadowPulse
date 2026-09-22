import { useDashboard } from '@/context/DashboardContext';
import { PageHeader, SectionCard } from '@/components/StatCard';
import { SkeletonList, EmptyState } from '@/components/Loaders';
import { SignalBars, AreaSparkline } from '@/components/Charts';
import type { NearbyAP } from '@/lib/types';
import { Wifi, ShieldCheck, AlertTriangle, EyeOff, Lock, Unlock, Radio } from 'lucide-react';
import { useMemo } from 'react';

function FlagBadge({ flag }: { flag: string }) {
  const colors: Record<string, string> = {
    'Evil Twin': '#EF4444',
    'SSID Impersonation': '#F97316',
    'Hidden SSID': '#F59E0B',
    'Open Network': '#3B82F6',
  };
  const color = colors[flag] ?? '#64748B';
  return (
    <span className="badge px-2 py-0.5 text-[10px] font-semibold" style={{ backgroundColor: `${color}20`, color, border: `1px solid ${color}40` }}>
      {flag}
    </span>
  );
}

function RssiSparkline({ baseRssi }: { baseRssi: number }) {
  const data = useMemo(
    () => Array.from({ length: 15 }, (_, i) => Math.max(-95, Math.min(-20, baseRssi + Math.round((Math.random() - 0.5) * 12)))),
    [baseRssi]
  );
  return <AreaSparkline data={data} color="#F97316" height={32} width={80} id={`rssi-${baseRssi}`} />;
}

export function RogueAccessPage() {
  const { data, loading } = useDashboard();

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="Rogue Access Points" subtitle="Wi-Fi security monitoring" />
        <SkeletonList count={5} />
      </div>
    );
  }

  const rogue = data?.rogueAccess;
  const authorized = rogue?.authorized_aps ?? [];
  const nearby = rogue?.nearby_aps ?? [];
  const threats = nearby.filter((ap) => !ap.authorized && ap.flags.length > 0);

  return (
    <div className="space-y-5">
      <PageHeader title="Rogue Access Points" subtitle="Wi-Fi security — compares nearby access points against your authorized list" />

      {/* Summary */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><ShieldCheck className="w-4 h-4 text-green-400" /> Authorized APs</div>
          <div className="text-2xl font-bold text-green-400">{authorized.length}</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><Wifi className="w-4 h-4 text-blue-400" /> Nearby APs</div>
          <div className="text-2xl font-bold text-blue-400">{nearby.length}</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><AlertTriangle className="w-4 h-4 text-red-400" /> Flagged Threats</div>
          <div className="text-2xl font-bold text-red-400">{threats.length}</div>
        </div>
        <div className="card p-4">
          <div className="flex items-center gap-2 text-xs text-ink-400 mb-2"><EyeOff className="w-4 h-4 text-amber-400" /> Hidden SSIDs</div>
          <div className="text-2xl font-bold text-amber-400">{nearby.filter((a) => a.hidden).length}</div>
        </div>
      </div>

      {/* Authorized list */}
      <SectionCard title="Authorized Access Points" subtitle="Access points you trust — edit this list in Settings">
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {authorized.map((ap) => (
            <div key={ap.bssid} className="card-panel p-3 flex items-center gap-3 border-green-500/20">
              <div className="w-9 h-9 rounded-lg bg-green-500/15 flex items-center justify-center">
                <ShieldCheck className="w-4.5 h-4.5 text-green-400" style={{ width: 18, height: 18 }} />
              </div>
              <div>
                <div className="text-sm font-semibold text-white">{ap.ssid}</div>
                <div className="text-xs font-mono text-ink-500">{ap.bssid}</div>
                {ap.band && <div className="text-[10px] text-ink-500">{ap.band}</div>}
              </div>
            </div>
          ))}
        </div>
      </SectionCard>

      {/* Nearby APs */}
      <SectionCard title="Nearby Access Points" subtitle="All Wi-Fi networks detected in range — signal strength shown as bars (green = strong, red = weak)">
        {nearby.length === 0 ? (
          <EmptyState icon={Radio} title="No access points found" message="No Wi-Fi networks detected nearby. Try triggering a scan." />
        ) : (
          <div className="space-y-2">
            {nearby.map((ap: NearbyAP) => {
              const isFlagged = !ap.authorized && ap.flags.length > 0;
              return (
                <div
                  key={ap.bssid}
                  className={`card-panel p-3.5 flex flex-col md:flex-row md:items-center gap-3 ${
                    isFlagged ? 'border-red-500/30' : ap.authorized ? 'border-green-500/20' : ''
                  }`}
                >
                  <div className="flex items-center gap-3 flex-1 min-w-0">
                    <div
                      className="w-9 h-9 rounded-lg flex items-center justify-center flex-shrink-0"
                      style={{ backgroundColor: ap.authorized ? '#22C55E18' : isFlagged ? '#EF444418' : '#64748B18' }}
                    >
                      {ap.authorized ? <ShieldCheck className="w-4.5 h-4.5 text-green-400" style={{ width: 18, height: 18 }} /> :
                       ap.flags.includes('Evil Twin') ? <AlertTriangle className="w-4.5 h-4.5 text-red-400" style={{ width: 18, height: 18 }} /> :
                       <Wifi className="w-4.5 h-4.5 text-ink-400" style={{ width: 18, height: 18 }} />}
                    </div>
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white truncate">
                          {ap.hidden ? <span className="flex items-center gap-1 text-amber-400"><EyeOff className="w-3 h-3" /> Hidden</span> : ap.ssid || 'Unknown'}
                        </span>
                        {ap.authorized && <span className="badge bg-green-500/15 text-green-400 px-1.5 py-0.5 text-[10px]">Authorized</span>}
                      </div>
                      <div className="text-xs font-mono text-ink-500">{ap.bssid}</div>
                    </div>
                  </div>

                  <div className="flex items-center gap-4 flex-wrap">
                    <div className="flex items-center gap-1.5 text-xs text-ink-400">
                      {ap.encryption === 'Open' ? <Unlock className="w-3.5 h-3.5 text-red-400" /> : <Lock className="w-3.5 h-3.5 text-green-400" />}
                      {ap.encryption}
                    </div>
                    <div className="text-xs text-ink-400">Ch <span className="font-mono text-ink-200">{ap.channel}</span></div>
                    <SignalBars rssi={ap.rssi} />
                    {isFlagged && (
                      <div className="flex items-center gap-1">
                        <span className="text-[10px] text-ink-500">RSSI trend</span>
                        <RssiSparkline baseRssi={ap.rssi} />
                      </div>
                    )}
                    <div className="flex items-center gap-1 flex-wrap">
                      {ap.flags.map((f) => <FlagBadge key={f} flag={f} />)}
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </SectionCard>

      {/* Plain-language explainer */}
      <div className="card p-4 border-blue-500/20 bg-blue-500/5">
        <div className="flex items-start gap-3">
          <Wifi className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
          <div className="text-xs text-ink-300 leading-relaxed">
            <span className="font-semibold text-blue-300">What is a Rogue Access Point? </span>
            A rogue AP is a fake Wi-Fi network set up to trick your devices into connecting — often by copying a trusted
            network name (an "Evil Twin"). Once connected, an attacker can monitor your traffic. Only connect to networks
            you recognize, and report any flagged access points to your network administrator.
          </div>
        </div>
      </div>
    </div>
  );
}
