import { useDashboard } from '@/context/DashboardContext';
import { PageHeader, SectionCard } from '@/components/StatCard';
import { SkeletonTable, EmptyState } from '@/components/Loaders';
import { NetworkTopology } from '@/components/NetworkTopology';
import type { DeviceInfo } from '@/lib/types';
import { Laptop, Router, AlertTriangle, RefreshCw, Network } from 'lucide-react';
import { useState } from 'react';

export function DevicesPage() {
  const { data, loading, triggerScan, actionLoading } = useDashboard();
  const [filter, setFilter] = useState<'all' | 'suspicious'>('all');

  if (loading && !data) {
    return (
      <div>
        <PageHeader title="Connected Devices" subtitle="Devices currently on your network" />
        <SkeletonTable rows={7} cols={5} />
      </div>
    );
  }

  const devices = data?.network.devices ?? [];
  const filtered = filter === 'suspicious' ? devices.filter((d) => d.suspicious) : devices;
  const suspiciousCount = devices.filter((d) => d.suspicious).length;

  return (
    <div className="space-y-5">
      <PageHeader
        title="Connected Devices"
        subtitle="Devices discovered on your network — data from /api/network"
        action={
          <button onClick={triggerScan} disabled={actionLoading} className="btn-outline text-xs">
            <RefreshCw className={`w-3.5 h-3.5 ${actionLoading ? 'animate-spin' : ''}`} />
            Rescan Network
          </button>
        }
      />

      {/* Network topology */}
      <SectionCard title="Network Topology" subtitle="Visual map of your network — the router is at the center, connected devices surround it. Suspicious devices are highlighted in red.">
        {devices.length === 0 ? (
          <EmptyState icon={Network} title="No devices to map" message="No devices discovered. Try rescanning the network." />
        ) : (
          <NetworkTopology devices={devices} size={460} />
        )}
      </SectionCard>

      <div className="flex items-center gap-2">
        <button
          onClick={() => setFilter('all')}
          className={`badge ${filter === 'all' ? 'bg-blue-500/20 text-blue-300 border border-blue-500/40' : 'bg-soc-bg text-ink-400 border border-soc-border'}`}
        >
          All ({devices.length})
        </button>
        <button
          onClick={() => setFilter('suspicious')}
          className={`badge ${filter === 'suspicious' ? 'bg-red-500/20 text-red-300 border border-red-500/40' : 'bg-soc-bg text-ink-400 border border-soc-border'}`}
        >
          <AlertTriangle className="w-3 h-3" /> Suspicious ({suspiciousCount})
        </button>
      </div>

      {filtered.length === 0 ? (
        <EmptyState icon={Laptop} title="No devices found" message={filter === 'suspicious' ? 'No suspicious devices detected. All connected devices look normal.' : 'No devices discovered. Try rescanning the network.'} />
      ) : (
        <div className="card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-soc-border text-xs text-ink-400 uppercase tracking-wide">
                  <th className="text-left p-3 font-medium">IP Address</th>
                  <th className="text-left p-3 font-medium">MAC Address</th>
                  <th className="text-left p-3 font-medium">Vendor</th>
                  <th className="text-left p-3 font-medium">Hostname</th>
                  <th className="text-left p-3 font-medium">Role</th>
                  <th className="text-left p-3 font-medium">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-soc-border">
                {filtered.map((d: DeviceInfo) => (
                  <tr key={d.ip} className="hover:bg-soc-hover transition-colors">
                    <td className="p-3 font-mono text-ink-200">{d.ip}</td>
                    <td className="p-3 font-mono text-ink-400 text-xs">{d.mac}</td>
                    <td className="p-3">
                      <span className={d.vendor === 'Unknown' ? 'text-amber-400 font-medium' : 'text-ink-200'}>{d.vendor}</span>
                    </td>
                    <td className="p-3 text-ink-300">{d.hostname ?? '—'}</td>
                    <td className="p-3">
                      {d.is_gateway ? (
                        <span className="badge bg-blue-500/15 text-blue-300 border border-blue-500/30">
                          <Router className="w-3 h-3" /> Gateway
                        </span>
                      ) : (
                        <span className="text-ink-500 text-xs">Device</span>
                      )}
                    </td>
                    <td className="p-3">
                      {d.suspicious ? (
                        <span className="badge bg-red-500/15 text-red-400 border border-red-500/30">
                          <AlertTriangle className="w-3 h-3" /> Suspicious
                        </span>
                      ) : (
                        <span className="flex items-center gap-1.5 text-xs text-green-400">
                          <span className="w-1.5 h-1.5 rounded-full bg-green-400" /> Normal
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {suspiciousCount > 0 && (
        <div className="card p-4 border-amber-500/30 bg-amber-500/5">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-amber-400 flex-shrink-0 mt-0.5" />
            <div className="text-xs text-ink-300 leading-relaxed">
              <span className="font-semibold text-amber-300">{suspiciousCount} suspicious device{suspiciousCount > 1 ? 's' : ''} detected. </span>
              These devices have unknown vendors or unrecognized hostnames. Check that you recognize each device —
              an unknown device on your network could be an attacker or compromised device.
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
