import { useDashboard } from '@/context/DashboardContext';
import { Activity, ShieldCheck, ShieldAlert, ShieldOff, WifiOff } from 'lucide-react';
import type { HealthState } from '@/lib/types';

const META: Record<HealthState, { label: string; color: string; bg: string; icon: typeof ShieldCheck }> = {
  secure: { label: 'Secure', color: '#22C55E', bg: 'bg-green-500/10', icon: ShieldCheck },
  monitoring: { label: 'Monitoring', color: '#F59E0B', bg: 'bg-amber-500/10', icon: Activity },
  under_attack: { label: 'Under Attack', color: '#EF4444', bg: 'bg-red-500/10', icon: ShieldAlert },
  monitoring_off: { label: 'Monitoring Off', color: '#64748B', bg: 'bg-ink-500/10', icon: ShieldOff },
  offline: { label: 'Offline', color: '#F59E0B', bg: 'bg-amber-500/10', icon: WifiOff },
};

export function HealthIndicator({ size = 'md' }: { size?: 'sm' | 'md' | 'lg' }) {
  const { health } = useDashboard();
  const m = META[health];
  const Icon = m.icon;
  const dim = size === 'lg' ? 'w-16 h-16' : size === 'sm' ? 'w-9 h-9' : 'w-12 h-12';
  const iconSize = size === 'lg' ? 'w-8 h-8' : 'w-5 h-5';
  const pulse = health === 'secure' || health === 'monitoring' || health === 'under_attack';

  return (
    <div className="flex items-center gap-3">
      <div
        className={`${dim} rounded-full ${m.bg} flex items-center justify-center relative`}
        style={{ boxShadow: pulse ? `0 0 20px ${m.color}40` : 'none' }}
      >
        {pulse && (
          <span
            className="absolute inset-0 rounded-full animate-ping opacity-40"
            style={{ backgroundColor: m.color }}
          />
        )}
        <Icon className={`${iconSize} relative z-10`} style={{ color: m.color }} />
      </div>
      {size !== 'sm' && (
        <div>
          <div className="text-xs text-ink-400 uppercase tracking-wide font-medium">Network Status</div>
          <div className="text-lg font-bold" style={{ color: m.color }}>
            {m.label}
          </div>
        </div>
      )}
    </div>
  );
}

export function MonitoringPill() {
  const { data, online } = useDashboard();
  const on = data?.status.monitoring ?? false;
  const color = !online ? '#F59E0B' : on ? '#22C55E' : '#64748B';
  return (
    <div
      className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full text-xs font-semibold border"
      style={{ borderColor: `${color}50`, backgroundColor: `${color}15`, color }}
    >
      <span className="live-dot" style={{ color }} />
      {online ? (on ? 'Monitoring: ON' : 'Monitoring: OFF') : 'Backend Offline'}
    </div>
  );
}

export function PacketCounter() {
  const { data, online } = useDashboard();
  const rate = data?.network.packet_rate ?? 0;
  const total = data?.network.packet_count ?? 0;
  const active = online && (data?.status.monitoring ?? false);
  return (
    <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-soc-bg border border-soc-border">
      <Activity className={`w-4 h-4 ${active ? 'text-blue-400 animate-pulse-soft' : 'text-ink-500'}`} />
      <div className="flex flex-col leading-tight">
        <span className="text-[10px] text-ink-500 uppercase tracking-wide">Packets/s</span>
        <span className="text-xs font-mono font-semibold text-white tabular-nums">
          {active ? rate.toLocaleString() : '—'}
        </span>
      </div>
      <div className="w-px h-7 bg-soc-border mx-1" />
      <div className="flex flex-col leading-tight">
        <span className="text-[10px] text-ink-500 uppercase tracking-wide">Total</span>
        <span className="text-xs font-mono font-semibold text-ink-300 tabular-nums">
          {total.toLocaleString()}
        </span>
      </div>
    </div>
  );
}
