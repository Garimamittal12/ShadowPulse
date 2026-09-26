import { LayoutDashboard, Activity, BarChart3, Laptop, ScrollText, Settings, Radar, ShieldAlert } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { useDashboard } from '@/context/DashboardContext';

export type PageId = 'dashboard' | 'live' | 'analytics' | 'devices' | 'rogue' | 'ssl' | 'logs' | 'settings';

interface NavItem {
  id: PageId;
  label: string;
  icon: LucideIcon;
}

const NAV: NavItem[] = [
  { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
  { id: 'live', label: 'Live Monitoring', icon: Activity },
  { id: 'analytics', label: 'Attack Analytics', icon: BarChart3 },
  { id: 'devices', label: 'Devices', icon: Laptop },
  { id: 'rogue', label: 'Rogue Access Points', icon: Radar },
  { id: 'ssl', label: 'SSL Strip Monitor', icon: ShieldAlert },
  { id: 'logs', label: 'Logs', icon: ScrollText },
  { id: 'settings', label: 'Settings', icon: Settings },
];

export function Sidebar({ page, onNavigate, mobileOpen, onCloseMobile }: { page: PageId; onNavigate: (p: PageId) => void; mobileOpen: boolean; onCloseMobile: () => void }) {
  const { criticalCount, theme } = useDashboard();
  const light = theme === 'light';

  return (
    <>
      {mobileOpen && <div className="fixed inset-0 bg-black/60 z-40 md:hidden" onClick={onCloseMobile} />}
      <aside
        className={`fixed md:sticky top-0 left-0 z-50 h-screen w-64 border-r flex flex-col transition-transform duration-200 ${
          light ? 'bg-white border-ink-200' : 'bg-soc-panel border-soc-border'
        } ${
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0'
        }`}
      >
        <div className={`flex items-center gap-3 px-5 h-16 border-b ${light ? 'border-ink-200' : 'border-soc-border'}`}>
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center shadow-glow">
            <Radar className="w-5 h-5 text-white" />
          </div>
          <div>
            <div className={`text-sm font-bold tracking-tight ${light ? 'text-ink-900' : 'text-white'}`}>ShadowPulse</div>
            <div className="text-[10px] text-ink-500 uppercase tracking-widest">Network IDS</div>
          </div>
        </div>

        <nav className="flex-1 overflow-y-auto py-4 px-3 space-y-1">
          {NAV.map((item) => {
            const active = page === item.id;
            const Icon = item.icon;
            return (
              <button
                key={item.id}
                onClick={() => { onNavigate(item.id); onCloseMobile(); }}
                className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all relative ${
                  active
                    ? 'bg-blue-500/15 text-blue-600 border border-blue-500/30'
                    : light
                      ? 'text-ink-600 hover:bg-ink-100 hover:text-ink-900 border border-transparent'
                      : 'text-ink-400 hover:bg-soc-hover hover:text-white border border-transparent'
                }`}
              >
                {active && <span className="absolute left-0 top-1/2 -translate-y-1/2 w-1 h-6 rounded-r-full bg-blue-500" />}
                <Icon className={`w-4.5 h-4.5 ${active ? 'text-blue-500' : ''}`} style={{ width: 18, height: 18 }} />
                {item.label}
                {item.id === 'dashboard' && criticalCount > 0 && (
                  <span className="ml-auto badge bg-red-500/20 text-red-500 px-1.5 py-0.5 text-[10px] animate-pulse-soft">
                    {criticalCount}
                  </span>
                )}
              </button>
            );
          })}
        </nav>

        <div className={`px-4 py-4 border-t ${light ? 'border-ink-200' : 'border-soc-border'}`}>
          <div className="text-[10px] text-ink-500 leading-relaxed">
            ShadowPulse v1.0 — Real-time network intrusion detection. Polling backend every 3s.
          </div>
        </div>
      </aside>
    </>
  );
}

export { NAV };
