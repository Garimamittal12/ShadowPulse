import { SEVERITY_META, SEVERITY_ORDER } from '@/lib/detectors';
import type { Severity } from '@/lib/types';
import { AlertTriangle, ShieldAlert, Shield, Info, AlertCircle } from 'lucide-react';

const ICONS: Record<Severity, typeof Shield> = {
  critical: ShieldAlert,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  info: Shield,
};

export function SeverityBadge({ severity, size = 'sm' }: { severity: Severity; size?: 'sm' | 'xs' }) {
  const meta = SEVERITY_META[severity];
  const Icon = ICONS[severity];
  return (
    <span
      className={`badge ${meta.bg} ${meta.text} ${meta.border} border ${size === 'xs' ? 'px-2 py-0.5 text-[10px]' : ''}`}
      style={{ color: meta.color }}
    >
      <Icon className={size === 'xs' ? 'w-2.5 h-2.5' : 'w-3 h-3'} />
      <span className="font-semibold">{meta.label}</span>
    </span>
  );
}

export function SeverityDot({ severity }: { severity: Severity }) {
  const meta = SEVERITY_META[severity];
  return (
    <span
      className="inline-block w-2 h-2 rounded-full"
      style={{ backgroundColor: meta.color, boxShadow: `0 0 8px ${meta.color}80` }}
    />
  );
}

export { SEVERITY_ORDER, SEVERITY_META };
