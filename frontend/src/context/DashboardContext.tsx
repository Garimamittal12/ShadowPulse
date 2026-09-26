import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import type { Alert, DashboardData, HealthState, Severity } from '@/lib/types';
import { api } from '@/lib/api';

export interface Toast {
  id: string;
  severity: Severity;
  title: string;
  message: string;
}

interface DashboardContextValue {
  data: DashboardData | null;
  loading: boolean;
  error: string | null;
  online: boolean;
  health: HealthState;
  criticalCount: number;
  unreadCritical: number;
  markCriticalRead: () => void;
  toasts: Toast[];
  dismissToast: (id: string) => void;
  pushToast: (t: Omit<Toast, 'id'>) => void;
  startMonitoring: () => Promise<void>;
  stopMonitoring: () => Promise<void>;
  triggerScan: () => Promise<void>;
  actionLoading: boolean;
  theme: 'dark' | 'light';
  toggleTheme: () => void;
  refresh: () => void;
}

const DashboardContext = createContext<DashboardContextValue | null>(null);

export function useDashboard() {
  const ctx = useContext(DashboardContext);
  if (!ctx) throw new Error('useDashboard must be used within DashboardProvider');
  return ctx;
}

const FALLBACK_POLL_INTERVAL = 30000;
const WS_URL = (import.meta.env.VITE_WS_URL as string) ||
  `${(import.meta.env.VITE_API_BASE_URL as string || 'http://localhost:5000').replace(/^http/, 'ws')}/ws`;

export function DashboardProvider({ children }: { children: ReactNode }) {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [online, setOnline] = useState(true);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [actionLoading, setActionLoading] = useState(false);
  const [theme, setTheme] = useState<'dark' | 'light'>('dark');
  const [unreadCritical, setUnreadCritical] = useState(0);
  const knownAlertIds = useRef<Set<string>>(new Set());
  const firstLoad = useRef(true);

  const pushToast = useCallback((t: Omit<Toast, 'id'>) => {
    const id = `toast-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
    setToasts((prev) => [...prev, { ...t, id }].slice(-4));
    setTimeout(() => setToasts((prev) => prev.filter((x) => x.id !== id)), 7000);
  }, []);

  const dismissToast = useCallback((id: string) => {
    setToasts((prev) => prev.filter((x) => x.id !== id));
  }, []);

  const fetchAll = useCallback(async () => {
    try {
      const result = await api.getAll();

      // Detect new critical/high alerts to toast (after initial load)
      if (!firstLoad.current && result.status.monitoring) {
        const newCritical: Alert[] = [];
        for (const a of result.alerts) {
          if (!knownAlertIds.current.has(a.id) && (a.details.severity === 'critical' || a.details.severity === 'high')) {
            newCritical.push(a);
          }
          knownAlertIds.current.add(a.id);
        }
        if (newCritical.length > 0) {
          setUnreadCritical((c) => c + newCritical.length);
        }
        for (const a of newCritical.slice(0, 2)) {
          pushToast({
            severity: a.details.severity,
            title: `${a.details.severity === 'critical' ? 'Critical' : 'High'} Alert: ${a.alert_type}`,
            message: a.details.description ?? 'New threat detected on your network',
          });
        }
      } else {
        result.alerts.forEach((a) => knownAlertIds.current.add(a.id));
        firstLoad.current = false;
      }

      setData(result);
      setOnline(true);
      setError(null);
    } catch (e) {
      setOnline(false);
      setError(e instanceof Error ? e.message : 'Failed to reach backend');
    } finally {
      setLoading(false);
    }
  }, [pushToast]);

  useEffect(() => {
    fetchAll();
    const pollId = setInterval(fetchAll, FALLBACK_POLL_INTERVAL);
    let socket: WebSocket | null = null;
    let reconnectTimer: number | undefined;
    let disposed = false;

    const connect = () => {
      if (disposed) return;
      socket = new WebSocket(WS_URL);
      socket.onopen = () => {
        // Refresh once after reconnect to recover any events missed offline.
        fetchAll();
      };
      socket.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as { event?: string };
          if (message.event === 'alert' || message.event === 'device_discovered') {
            fetchAll();
          }
        } catch {
          // Ignore malformed or non-JSON frames and keep the connection alive.
        }
      };
      socket.onclose = () => {
        if (!disposed) reconnectTimer = window.setTimeout(connect, 3000);
      };
      socket.onerror = () => socket?.close();
    };

    connect();
    return () => {
      disposed = true;
      clearInterval(pollId);
      if (reconnectTimer !== undefined) window.clearTimeout(reconnectTimer);
      socket?.close();
    };
  }, [fetchAll]);

  const startMonitoring = useCallback(async () => {
    setActionLoading(true);
    try {
      await api.start();
      await fetchAll();
    } catch {
      setError('Failed to start monitoring');
    } finally {
      setActionLoading(false);
    }
  }, [fetchAll]);

  const stopMonitoring = useCallback(async () => {
    setActionLoading(true);
    try {
      await api.stop();
      await fetchAll();
    } catch {
      setError('Failed to stop monitoring');
    } finally {
      setActionLoading(false);
    }
  }, [fetchAll]);

  const triggerScan = useCallback(async () => {
    setActionLoading(true);
    try {
      await api.scan();
      await fetchAll();
    } catch {
      setError('Failed to trigger scan');
    } finally {
      setActionLoading(false);
    }
  }, [fetchAll]);

  const toggleTheme = useCallback(() => {
    setTheme((t) => (t === 'dark' ? 'light' : 'dark'));
  }, []);

  const refresh = useCallback(() => {
    fetchAll();
  }, [fetchAll]);

  const health: HealthState = useMemo(() => {
    if (!online) return 'offline';
    if (!data?.status.monitoring) return 'monitoring_off';
    // Use the backend confidence-weighted threat score, not raw alert count.
    // Thresholds mirror statistics.py _threat_score():
    //   0-29  → secure      (normal network noise, no confirmed attacks)
    //   30-59 → monitoring  (suspicious anomalies, low confidence)
    //   60-100→ under_attack (confirmed MITM indicators)
    const score = data.statistics?.threat_score ?? 0;
    if (score >= 60) return 'under_attack';
    if (score >= 30) return 'monitoring';
    return 'secure';
  }, [data, online]);

  const criticalCount = useMemo(
    () => data?.alerts.filter((a) => a.details.severity === 'critical').length ?? 0,
    [data]
  );

  const markCriticalRead = useCallback(() => {
    setUnreadCritical(0);
  }, []);

  const value: DashboardContextValue = {
    data,
    loading,
    error,
    online,
    health,
    criticalCount,
    unreadCritical,
    markCriticalRead,
    toasts,
    dismissToast,
    pushToast,
    startMonitoring,
    stopMonitoring,
    triggerScan,
    actionLoading,
    theme,
    toggleTheme,
    refresh,
  };

  return <DashboardContext.Provider value={value}>{children}</DashboardContext.Provider>;
}
