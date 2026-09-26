import { useState, type ReactNode } from 'react';
import { Sidebar, type PageId } from './Sidebar';
import { TopBar } from './TopBar';
import { ToastContainer } from './ToastContainer';
import { useDashboard } from '@/context/DashboardContext';

const TITLES: Record<PageId, string> = {
  dashboard: 'Dashboard',
  live: 'Live Monitoring',
  analytics: 'Attack Analytics',
  devices: 'Connected Devices',
  rogue: 'Rogue Access Points',
  ssl: 'SSL Strip Monitor',
  logs: 'Alert Logs',
  settings: 'Settings',
};

export function Layout({ page, onNavigate, children }: { page: PageId; onNavigate: (p: PageId) => void; children: ReactNode }) {
  const { theme } = useDashboard();
  const [mobileOpen, setMobileOpen] = useState(false);

  return (
    <div className={theme === 'light' ? 'light' : ''}>
      <div className="min-h-screen bg-soc-bg text-ink-100 flex">
        <Sidebar
          page={page}
          onNavigate={onNavigate}
          mobileOpen={mobileOpen}
          onCloseMobile={() => setMobileOpen(false)}
        />
        <div className="flex-1 flex flex-col min-w-0">
          <TopBar onOpenMobile={() => setMobileOpen(true)} title={TITLES[page]} onNavigate={onNavigate} />
          <main className="flex-1 overflow-y-auto p-4 md:p-6 max-w-[1600px] w-full mx-auto">
            {children}
          </main>
        </div>
        <ToastContainer />
      </div>
    </div>
  );
}
