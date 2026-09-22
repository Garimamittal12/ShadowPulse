import { useDashboard } from '@/context/DashboardContext';
import { PageHeader, SectionCard } from '@/components/StatCard';
import { DETECTORS } from '@/lib/detectors';
import type { DetectorKey } from '@/lib/types';
import { Play, Square, Radar, Activity, ShieldCheck } from 'lucide-react';

/** Operational controls only. Configuration that is not applied by the
 * backend is deliberately not presented as a setting. */
export function SettingsPage() {
  const { data, startMonitoring, stopMonitoring, triggerScan, actionLoading } = useDashboard();
  const status = data?.status;
  const detectorStates = status?.detectors_enabled ?? {};

  return (
    <div className="space-y-5">
      <PageHeader title="Sensor Operations" subtitle="Control the local capture sensor and review its live state" />

      <SectionCard title="Monitoring Controls" subtitle="Packet capture requires Npcap and Administrator privileges on Windows">
        <div className="flex flex-wrap items-center gap-3">
          <button onClick={startMonitoring} disabled={actionLoading || status?.monitoring} className="btn-primary">
            <Play className="w-4 h-4" /> Start Monitoring
          </button>
          <button onClick={stopMonitoring} disabled={actionLoading || !status?.monitoring} className="btn-danger">
            <Square className="w-4 h-4" /> Stop Monitoring
          </button>
          <button onClick={triggerScan} disabled={actionLoading} className="btn-outline">
            <Radar className="w-4 h-4" /> Discover Devices
          </button>
          <div className="ml-auto text-xs text-ink-400">
            Sensor: <span className={status?.monitoring ? 'font-semibold text-green-400' : 'font-semibold text-ink-500'}>
              {status?.monitoring ? 'RUNNING' : 'STOPPED'}
            </span>
          </div>
        </div>
      </SectionCard>

      <SectionCard title="Capture Context" subtitle="Resolved automatically from the active network adapter at sensor startup">
        <dl className="grid grid-cols-1 sm:grid-cols-3 gap-4 text-sm">
          <div><dt className="text-xs text-ink-500">Interface</dt><dd className="mt-1 font-mono text-ink-200">{status?.interface ?? 'Not resolved'}</dd></div>
          <div><dt className="text-xs text-ink-500">Local IP</dt><dd className="mt-1 font-mono text-ink-200">{status?.local_ip ?? 'Not resolved'}</dd></div>
          <div><dt className="text-xs text-ink-500">Monitored subnet</dt><dd className="mt-1 font-mono text-ink-200">{status?.network_range ?? 'Not resolved'}</dd></div>
        </dl>
      </SectionCard>

      <SectionCard title="Detection Modules" subtitle="Current runtime state. Module configuration is managed in shadowpulse.conf and takes effect after restart.">
        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-3">
          {(Object.keys(DETECTORS) as DetectorKey[]).map((key) => {
            const enabled = detectorStates[key] ?? false;
            const meta = DETECTORS[key];
            return (
              <div key={key} className="card-panel p-3 flex items-center gap-3">
                {enabled ? <ShieldCheck className="w-5 h-5 text-green-400" /> : <Activity className="w-5 h-5 text-ink-500" />}
                <div>
                  <div className="text-sm font-semibold text-ink-200">{meta.label}</div>
                  <div className={enabled ? 'text-[10px] text-green-400' : 'text-[10px] text-ink-500'}>{enabled ? 'ACTIVE' : 'DISABLED'}</div>
                </div>
              </div>
            );
          })}
        </div>
      </SectionCard>
    </div>
  );
}
