import { useState } from 'react';
import { DashboardProvider } from '@/context/DashboardContext';
import { Layout } from '@/components/Layout';
import type { PageId } from '@/components/Sidebar';
import { DashboardPage } from '@/pages/DashboardPage';
import { LivePage } from '@/pages/LivePage';
import { AnalyticsPage } from '@/pages/AnalyticsPage';
import { DevicesPage } from '@/pages/DevicesPage';
import { LogsPage } from '@/pages/LogsPage';
import { SettingsPage } from '@/pages/SettingsPage';

function App() {
  const [page, setPage] = useState<PageId>('dashboard');

  return (
    <DashboardProvider>
      <Layout page={page} onNavigate={setPage}>
        {page === 'dashboard' && <DashboardPage />}
        {page === 'live' && <LivePage />}
        {page === 'analytics' && <AnalyticsPage />}
        {page === 'devices' && <DevicesPage />}
        {page === 'logs' && <LogsPage />}
        {page === 'settings' && <SettingsPage />}
      </Layout>
    </DashboardProvider>
  );
}

export default App;
