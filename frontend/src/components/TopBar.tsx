import { useState } from 'react';
import { Menu, Bell, Sun, Moon, X, ShieldAlert, User, Settings as SettingsIcon, LogOut, ChevronDown } from 'lucide-react';
import { useDashboard } from '@/context/DashboardContext';
import { MonitoringPill, PacketCounter } from './HealthIndicator';
import { formatTime } from '@/lib/format';
import { SEVERITY_META } from '@/lib/detectors';
import type { PageId } from './Sidebar';

export function TopBar({ onOpenMobile, title, onNavigate }: { onOpenMobile: () => void; title: string; onNavigate: (p: PageId) => void }) {
  const { theme, toggleTheme, data, online, unreadCritical, markCriticalRead, pushToast } = useDashboard();
  const light = theme === 'light';
  const [bellOpen, setBellOpen] = useState(false);
  const [accountOpen, setAccountOpen] = useState(false);
  const [profileOpen, setProfileOpen] = useState(false);
  const recentCritical = data?.alerts.filter((a) => a.details.severity === 'critical' || a.details.severity === 'high').slice(0, 8) ?? [];

  function openBell() {
    setBellOpen(true);
    markCriticalRead();
  }

  function handleLogout() {
    setAccountOpen(false);
    pushToast({ severity: 'info', title: 'Signed out', message: 'You have been logged out of ShadowPulse.' });
  }

  return (
    <header className={`sticky top-0 z-30 h-16 backdrop-blur border-b flex items-center gap-3 px-4 md:px-6 ${light ? 'bg-white/95 border-ink-200' : 'bg-soc-panel/95 border-soc-border'}`}>
      <button onClick={onOpenMobile} className="md:hidden btn-ghost p-2">
        <Menu className="w-5 h-5" />
      </button>

      <h1 className="text-base font-semibold text-white hidden sm:block">{title}</h1>

      <div className="flex-1" />

      <div className="hidden lg:block">
        <PacketCounter />
      </div>

      <div className={`hidden sm:flex items-center gap-1.5 px-3 py-1.5 rounded-lg border text-xs ${light ? 'bg-ink-50 border-ink-200' : 'bg-soc-bg border-soc-border'}`}>
        <span className="text-ink-500">Interface:</span>
        <span className="font-mono font-semibold text-ink-200">{data?.status.interface ?? '—'}</span>
      </div>

      {/* Notification bell with persistent unread badge */}
      <div className="relative">
        <button
          onClick={() => (bellOpen ? setBellOpen(false) : openBell())}
          className="relative btn-ghost p-2"
          aria-label="Notifications"
        >
          <Bell className="w-5 h-5" />
          {unreadCritical > 0 && (
            <span className="absolute top-1 right-1 min-w-4 h-4 px-1 rounded-full bg-red-500 text-white text-[9px] font-bold flex items-center justify-center animate-pulse-soft">
              {unreadCritical > 9 ? '9+' : unreadCritical}
            </span>
          )}
        </button>
        {bellOpen && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setBellOpen(false)} />
            <div className="absolute right-0 top-12 z-50 w-80 max-h-96 overflow-y-auto card shadow-xl animate-slide-up">
              <div className={`flex items-center justify-between p-3 border-b sticky top-0 z-10 ${light ? 'border-ink-200 bg-white' : 'border-soc-border bg-soc-card'}`}>
                <span className="text-sm font-semibold text-white">Critical Alerts</span>
                <button onClick={() => setBellOpen(false)} className={`text-ink-400 hover:${light ? 'text-ink-900' : 'text-white'}`}>
                  <X className="w-4 h-4" />
                </button>
              </div>
              {recentCritical.length === 0 ? (
                <div className="p-6 text-center text-xs text-ink-400">No critical alerts. Your network is secure.</div>
              ) : (
                <div className="divide-y divide-soc-border">
                  {recentCritical.map((a) => {
                    const sev = SEVERITY_META[a.details.severity];
                    return (
                      <div key={a.id} className={`p-3 hover:${light ? 'bg-ink-100' : 'bg-soc-hover'}`}>
                        <div className="flex items-center gap-2">
                          <ShieldAlert className="w-4 h-4 flex-shrink-0" style={{ color: sev.color }} />
                          <div className="flex-1 min-w-0">
                            <div className="text-xs font-semibold text-white truncate">{a.alert_type}</div>
                            <div className="text-[11px] text-ink-500">{formatTime(a.timestamp)} — {a.details.description}</div>
                          </div>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          </>
        )}
      </div>

      {/* Theme toggle */}
      <button onClick={toggleTheme} className="btn-ghost p-2" aria-label="Toggle theme">
        {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
      </button>

      {/* Account dropdown */}
      <div className="relative">
        <button
          onClick={() => setAccountOpen((o) => !o)}
          className="flex items-center gap-1.5 btn-ghost p-1.5 pr-2"
          aria-label="Account"
        >
          <div className="w-7 h-7 rounded-full bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center">
            <User className="w-4 h-4 text-white" />
          </div>
          <ChevronDown className="w-3.5 h-3.5 text-ink-500" />
        </button>
        {accountOpen && (
          <>
            <div className="fixed inset-0 z-40" onClick={() => setAccountOpen(false)} />
            <div className="absolute right-0 top-12 z-50 w-56 card shadow-xl animate-slide-up overflow-hidden">
              <div className={`p-3 border-b ${light ? 'border-ink-200' : 'border-soc-border'}`}>
                <div className="text-sm font-semibold text-white">SOC Analyst</div>
                <div className="text-xs text-ink-500">analyst@shadowpulse.local</div>
              </div>
              <div className="py-1">
                <button onClick={() => { setProfileOpen(true); setAccountOpen(false); }} className={`w-full flex items-center gap-2 px-3 py-2 text-sm ${light ? 'text-ink-600 hover:bg-ink-100 hover:text-ink-900' : 'text-ink-300 hover:bg-soc-hover hover:text-white'}`}>
                  <User className="w-4 h-4" /> Profile
                </button>
                <button onClick={() => { onNavigate('settings'); setAccountOpen(false); }} className={`w-full flex items-center gap-2 px-3 py-2 text-sm ${light ? 'text-ink-600 hover:bg-ink-100 hover:text-ink-900' : 'text-ink-300 hover:bg-soc-hover hover:text-white'}`}>
                  <SettingsIcon className="w-4 h-4" /> Preferences
                </button>
                <button onClick={handleLogout} className="w-full flex items-center gap-2 px-3 py-2 text-sm text-red-400 hover:bg-red-500/10">
                  <LogOut className="w-4 h-4" /> Log out
                </button>
              </div>
            </div>
          </>
        )}
      </div>

      <MonitoringPill />

      {/* Profile modal */}
      {profileOpen && (
        <>
          <div className="fixed inset-0 z-40 bg-black/50" onClick={() => setProfileOpen(false)} />
          <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 z-50 w-96 max-w-[90vw] card shadow-2xl animate-slide-up">
            <div className={`flex items-center justify-between p-4 border-b ${light ? 'border-ink-200' : 'border-soc-border'}`}>
              <h3 className="text-sm font-semibold text-white">Profile</h3>
              <button onClick={() => setProfileOpen(false)} className={`text-ink-400 hover:${light ? 'text-ink-900' : 'text-white'}`}>
                <X className="w-4 h-4" />
              </button>
            </div>
            <div className="p-5 space-y-4">
              <div className="flex items-center gap-4">
                <div className="w-16 h-16 rounded-full bg-gradient-to-br from-blue-500 to-blue-700 flex items-center justify-center shadow-glow">
                  <User className="w-8 h-8 text-white" />
                </div>
                <div>
                  <div className="text-base font-bold text-white">SOC Analyst</div>
                  <div className="text-xs text-ink-400">analyst@shadowpulse.local</div>
                  <div className="text-[11px] text-ink-500 mt-1">Role: Network Security Analyst</div>
                </div>
              </div>
              <div className="grid grid-cols-2 gap-3 text-xs">
                <div className="card-panel p-3">
                  <div className="text-ink-500 mb-1">Monitoring Status</div>
                  <div className={`font-semibold ${data?.status.monitoring ? 'text-green-400' : 'text-ink-400'}`}>
                    {data?.status.monitoring ? 'Active' : 'Stopped'}
                  </div>
                </div>
                <div className="card-panel p-3">
                  <div className="text-ink-500 mb-1">Active Detectors</div>
                  <div className="font-semibold text-white">
                    {Object.values(data?.status.detectors_enabled ?? {}).filter(Boolean).length}/7
                  </div>
                </div>
                <div className="card-panel p-3">
                  <div className="text-ink-500 mb-1">Total Alerts</div>
                  <div className="font-semibold text-white">{data?.alerts.length ?? 0}</div>
                </div>
                <div className="card-panel p-3">
                  <div className="text-ink-500 mb-1">Connected Devices</div>
                  <div className="font-semibold text-white">{data?.network.devices.length ?? 0}</div>
                </div>
              </div>
              <div className="text-[11px] text-ink-500 text-center pt-1">
                ShadowPulse v1.0 — Local session (no remote account)
              </div>
            </div>
          </div>
        </>
      )}
    </header>
  );
}
