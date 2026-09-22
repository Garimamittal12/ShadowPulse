import type { LucideIcon } from 'lucide-react';
import { TrendingUp, TrendingDown } from 'lucide-react';
import type { ReactNode } from 'react';

export function StatCard({
  icon: Icon,
  label,
  value,
  sub,
  color = '#3B82F6',
  trend,
  trendPct,
  children,
}: {
  icon: LucideIcon;
  label: string;
  value: string | number;
  sub?: string;
  color?: string;
  trend?: 'up' | 'down';
  trendPct?: number;
  children?: ReactNode;
}) {
  return (
    <div className="card p-4 hover:border-soc-hover transition-all">
      <div className="flex items-start justify-between">
        <div
          className="w-10 h-10 rounded-lg flex items-center justify-center"
          style={{ backgroundColor: `${color}18`, color }}
        >
          <Icon className="w-5 h-5" />
        </div>
        {trendPct !== undefined && trendPct !== 0 && (
          <span className={`text-xs font-medium flex items-center gap-0.5 ${trend === 'up' ? 'text-red-400' : 'text-green-400'}`}>
            {trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
            {Math.abs(trendPct)}%
            <span className="text-ink-500 hidden lg:inline">vs last hour</span>
          </span>
        )}
      </div>
      <div className="mt-3 flex items-end justify-between gap-2">
        <div>
          <div className="text-2xl font-bold text-white tabular-nums">{value}</div>
          <div className="text-xs text-ink-400 mt-0.5">{label}</div>
          {sub && <div className="text-[11px] text-ink-500 mt-0.5">{sub}</div>}
        </div>
        {children}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, action }: { title: string; subtitle?: string; action?: React.ReactNode }) {
  return (
    <div className="flex items-start justify-between gap-4 flex-wrap mb-5">
      <div>
        <h2 className="text-xl font-bold text-white">{title}</h2>
        {subtitle && <p className="text-sm text-ink-400 mt-0.5">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

export function SectionCard({ title, subtitle, children, action }: { title: string; subtitle?: string; children: React.ReactNode; action?: React.ReactNode }) {
  return (
    <div className="card p-4 md:p-5">
      <div className="flex items-center justify-between gap-2 mb-4">
        <div>
          <h3 className="text-sm font-semibold text-white">{title}</h3>
          {subtitle && <p className="text-xs text-ink-500 mt-0.5">{subtitle}</p>}
        </div>
        {action}
      </div>
      {children}
    </div>
  );
}
