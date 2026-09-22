import { LineChart, Line, AreaChart, Area, ResponsiveContainer, Tooltip, YAxis, RadialBarChart, RadialBar, PolarAngleAxis } from 'recharts';
import type { LucideIcon } from 'lucide-react';
import { Info } from 'lucide-react';
import { useState, useRef, useEffect } from 'react';

const TOOLTIP_STYLE = { background: '#161D2A', border: '1px solid #1F2A3C', borderRadius: 8, fontSize: 12 };

export function Sparkline({ data, color = '#3B82F6', height = 40, width = 120 }: { data: number[]; color?: string; height?: number; width?: number }) {
  const chartData = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width={width} height={height}>
      <LineChart data={chartData} margin={{ top: 2, right: 2, left: 2, bottom: 2 }}>
        <Line type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} dot={false} isAnimationActive={false} />
        <Tooltip contentStyle={TOOLTIP_STYLE} labelFormatter={() => ''} formatter={(v) => [`${v}`, '']} />
      </LineChart>
    </ResponsiveContainer>
  );
}

export function AreaSparkline({ data, color = '#3B82F6', height = 40, width = 120, id = 'spark' }: { data: number[]; color?: string; height?: number; width?: number; id?: string }) {
  const chartData = data.map((v, i) => ({ i, v }));
  return (
    <ResponsiveContainer width={width} height={height}>
      <AreaChart data={chartData} margin={{ top: 2, right: 2, left: 2, bottom: 2 }}>
        <defs>
          <linearGradient id={`sparkGrad-${id}`} x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor={color} stopOpacity={0.4} />
            <stop offset="95%" stopColor={color} stopOpacity={0} />
          </linearGradient>
        </defs>
        <Area type="monotone" dataKey="v" stroke={color} strokeWidth={1.5} fill={`url(#sparkGrad-${id})`} isAnimationActive={false} />
      </AreaChart>
    </ResponsiveContainer>
  );
}

export function GaugeChart({ value, max = 100, color = '#3B82F6', size = 180, label, sublabel }: { value: number; max?: number; color?: string; size?: number; label?: string; sublabel?: string }) {
  const data = [{ name: 'value', value: Math.min(value, max), fill: color }];
  return (
    <div className="flex flex-col items-center" style={{ width: size }}>
      <ResponsiveContainer width={size} height={size * 0.6}>
        <RadialBarChart innerRadius={`${70}%`} outerRadius={`${100}%`} data={data} startAngle={180} endAngle={0}>
          <PolarAngleAxis type="number" domain={[0, max]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: 'rgba(255,255,255,0.06)' }} dataKey="value" cornerRadius={8} angleAxisId={0} fill={color} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="-mt-8 text-center">
        <div className="text-2xl font-bold text-white tabular-nums">{value}{max === 100 ? '%' : ''}</div>
        {label && <div className="text-sm font-semibold" style={{ color }}>{label}</div>}
        {sublabel && <div className="text-xs text-ink-500 mt-0.5">{sublabel}</div>}
      </div>
    </div>
  );
}

export function MiniGauge({ value, max = 100, color = '#3B82F6', size = 90, label }: { value: number; max?: number; color?: string; size?: number; label?: string }) {
  const data = [{ name: 'value', value: Math.min(value, max), fill: color }];
  return (
    <div className="flex flex-col items-center">
      <ResponsiveContainer width={size} height={size * 0.55}>
        <RadialBarChart innerRadius={`${70}%`} outerRadius={`${100}%`} data={data} startAngle={180} endAngle={0}>
          <PolarAngleAxis type="number" domain={[0, max]} angleAxisId={0} tick={false} />
          <RadialBar background={{ fill: 'rgba(255,255,255,0.06)' }} dataKey="value" cornerRadius={6} angleAxisId={0} fill={color} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="-mt-5 text-center">
        <div className="text-sm font-bold text-white tabular-nums">{value}{max === 100 ? '%' : ''}</div>
        {label && <div className="text-[10px] text-ink-500">{label}</div>}
      </div>
    </div>
  );
}

export function Heatmap({ data, colorScale = ['#0F172A', '#1E3A5F', '#2563EB', '#EF4444'] }: { data: { day: string; hour: number; count: number }[]; colorScale?: string[] }) {
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const hours = Array.from({ length: 24 }, (_, i) => i);
  const maxCount = Math.max(...data.map((d) => d.count), 1);
  function cellColor(count: number): string {
    if (count === 0) return colorScale[0];
    const ratio = count / maxCount;
    if (ratio < 0.25) return colorScale[0];
    if (ratio < 0.5) return colorScale[1];
    if (ratio < 0.75) return colorScale[2];
    return colorScale[3];
  }
  return (
    <div className="overflow-x-auto">
      <div className="flex gap-1 min-w-[700px]">
        <div className="flex flex-col gap-1 pt-5 pr-1">
          {days.map((d) => (
            <div key={d} className="text-[10px] text-ink-500 h-4 flex items-center">{d}</div>
          ))}
        </div>
        <div className="flex-1">
          <div className="flex gap-1 mb-1">
            {hours.map((h) => (
              <div key={h} className="text-[9px] text-ink-600 w-5 text-center">{h % 6 === 0 ? `${h}h` : ''}</div>
            ))}
          </div>
          {days.map((day) => (
            <div key={day} className="flex gap-1 mb-1">
              {hours.map((h) => {
                const cell = data.find((d) => d.day === day && d.hour === h);
                const count = cell?.count ?? 0;
                return (
                  <div
                    key={h}
                    className="w-5 h-4 rounded-sm transition-colors hover:ring-1 hover:ring-blue-400/50"
                    style={{ backgroundColor: cellColor(count) }}
                    title={`${day} ${h}:00 — ${count} attacks`}
                  />
                );
              })}
            </div>
          ))}
        </div>
      </div>
      <div className="flex items-center gap-2 mt-3 ml-10">
        <span className="text-[10px] text-ink-500">Less</span>
        {colorScale.map((c, i) => (
          <div key={i} className="w-4 h-3 rounded-sm" style={{ backgroundColor: c }} />
        ))}
        <span className="text-[10px] text-ink-500">More</span>
      </div>
    </div>
  );
}

export function SignalBars({ rssi, showValue = true }: { rssi: number; showValue?: boolean }) {
  const pct = Math.max(0, Math.min(100, ((rssi + 90) / 60) * 100));
  const bars = pct > 75 ? 4 : pct > 50 ? 3 : pct > 25 ? 2 : 1;
  const color = pct > 66 ? '#22C55E' : pct > 33 ? '#F59E0B' : '#EF4444';
  return (
    <div className="flex items-center gap-1.5">
      <div className="flex items-end gap-0.5 h-4">
        {[1, 2, 3, 4].map((b) => (
          <div
            key={b}
            className="w-1 rounded-sm"
            style={{ height: `${b * 25}%`, backgroundColor: b <= bars ? color : '#334155' }}
          />
        ))}
      </div>
      {showValue && <span className="text-xs font-mono text-ink-400 tabular-nums">{rssi} dBm</span>}
    </div>
  );
}

export function InfoIcon({ text, size = 14 }: { text: string; size?: number }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);
  return (
    <span className="relative inline-flex" ref={ref}>
      <button
        onClick={(e) => { e.stopPropagation(); setOpen((o) => !o); }}
        className="text-ink-500 hover:text-blue-400 transition-colors"
        aria-label="More info"
      >
        <Info className="w-3.5 h-3.5" style={{ width: size, height: size }} />
      </button>
      {open && (
        <span className="absolute left-0 top-5 z-30 w-56 p-2 rounded-lg card shadow-xl text-[11px] text-ink-300 leading-relaxed animate-fade-in">
          {text}
        </span>
      )}
    </span>
  );
}

export function TrendArrow({ current, previous, invertColor = false }: { current: number; previous: number; invertColor?: boolean }) {
  if (previous === 0) return null;
  const pct = Math.round(((current - previous) / previous) * 100);
  if (pct === 0) return null;
  const up = pct > 0;
  const goodColor = invertColor ? (up ? 'text-red-400' : 'text-green-400') : (up ? 'text-red-400' : 'text-green-400');
  return (
    <span className={`text-xs font-medium flex items-center gap-0.5 ${goodColor}`}>
      {up ? '↑' : '↓'} {Math.abs(pct)}% <span className="text-ink-500 hidden sm:inline">vs last hour</span>
    </span>
  );
}
