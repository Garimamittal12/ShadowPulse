import type { Alert } from '@/lib/types';
import { DETECTORS, SEVERITY_META } from '@/lib/detectors';
import { SeverityBadge } from './SeverityBadge';
import { WhatDoesThisMean } from './WhatDoesThisMean';
import { relativeTime } from '@/lib/format';
import { Wifi, Network, Globe, Lock, FileCode2, Route, Server } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';

const ICONS: Record<string, LucideIcon> = {
  Network, Globe, Wifi, Lock, FileCode2, Route, Server,
};

export function AlertCard({ alert, compact = false }: { alert: Alert; compact?: boolean }) {
  const meta = DETECTORS[alert.detector];
  const Icon = ICONS[meta.icon] ?? Wifi;
  const sev = SEVERITY_META[alert.details.severity];

  return (
    <div
      className={`card p-3.5 transition-all hover:border-soc-hover ${compact ? '' : 'hover:shadow-glow'}`}
      style={{ borderLeftWidth: '3px', borderLeftColor: sev.color }}
    >
      <div className="flex items-start gap-3">
        <div
          className="flex-shrink-0 w-9 h-9 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${meta.color}20`, color: meta.color }}
        >
          <Icon className="w-4.5 h-4.5" style={{ width: 18, height: 18 }} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center justify-between gap-2 flex-wrap">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-sm font-semibold text-white">{meta.label}</span>
              <SeverityBadge severity={alert.details.severity} size="xs" />
            </div>
            <span className="text-[11px] text-ink-500 font-mono whitespace-nowrap">
              {relativeTime(alert.timestamp)}
            </span>
          </div>
          <p className="text-xs text-ink-400 mt-1">{alert.details.description ?? alert.alert_type}</p>
          {alert.details.ssid && (
            <p className="text-[11px] text-ink-500 mt-0.5 font-mono">SSID: {alert.details.ssid}</p>
          )}
          {!compact && <WhatDoesThisMean detector={alert.detector} />}
        </div>
      </div>
    </div>
  );
}
