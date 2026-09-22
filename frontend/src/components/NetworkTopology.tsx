import type { DeviceInfo } from '@/lib/types';
import { Router, Laptop, AlertTriangle } from 'lucide-react';

interface Node {
  id: string;
  x: number;
  y: number;
  device: DeviceInfo;
}

export function NetworkTopology({ devices, size = 480 }: { devices: DeviceInfo[]; size?: number }) {
  const gateway = devices.find((d) => d.is_gateway) ?? devices[0];
  const others = devices.filter((d) => d !== gateway);
  const cx = size / 2;
  const cy = size / 2;
  const radius = size * 0.36;

  const nodes: Node[] = others.map((device, i) => {
    const angle = (i / others.length) * 2 * Math.PI - Math.PI / 2;
    return {
      id: device.ip,
      x: cx + radius * Math.cos(angle),
      y: cy + radius * Math.sin(angle),
      device,
    };
  });

  return (
    <div className="flex justify-center">
      <svg width={size} height={size} className="max-w-full">
        {/* Connection lines */}
        {nodes.map((n) => (
          <line
            key={`line-${n.id}`}
            x1={cx}
            y1={cy}
            x2={n.x}
            y2={n.y}
            stroke={n.device.suspicious ? '#EF4444' : '#1F2A3C'}
            strokeWidth={n.device.suspicious ? 2 : 1}
            strokeDasharray={n.device.suspicious ? '4 2' : 'none'}
            opacity={0.6}
          />
        ))}

        {/* Gateway node */}
        <g>
          <circle cx={cx} cy={cy} r={28} fill="#0F172A" stroke="#3B82F6" strokeWidth={2} />
          <circle cx={cx} cy={cy} r={34} fill="none" stroke="#3B82F6" strokeWidth={1} opacity={0.3} />
          <foreignObject x={cx - 12} y={cy - 12} width={24} height={24}>
            <Router className="w-6 h-6 text-blue-400" />
          </foreignObject>
          <text x={cx} y={cy + 42} textAnchor="middle" className="fill-ink-300 text-[10px] font-mono">{gateway?.ip ?? '—'}</text>
          <text x={cx} y={cy + 54} textAnchor="middle" className="fill-ink-500 text-[9px]">Gateway</text>
        </g>

        {/* Device nodes */}
        {nodes.map((n) => (
          <g key={n.id}>
            <circle
              cx={n.x}
              cy={n.y}
              r={18}
              fill={n.device.suspicious ? '#EF444415' : '#111722'}
              stroke={n.device.suspicious ? '#EF4444' : '#334155'}
              strokeWidth={n.device.suspicious ? 2 : 1}
            />
            <foreignObject x={n.x - 8} y={n.y - 8} width={16} height={16}>
              {n.device.suspicious ? (
                <AlertTriangle className="w-4 h-4 text-red-400" />
              ) : (
                <Laptop className="w-4 h-4 text-ink-400" />
              )}
            </foreignObject>
            <text x={n.x} y={n.y + 30} textAnchor="middle" className="fill-ink-400 text-[9px] font-mono">{n.device.hostname ?? n.device.ip}</text>
          </g>
        ))}
      </svg>
    </div>
  );
}
