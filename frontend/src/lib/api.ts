/**
 * frontend/src/lib/api.ts
 * ShadowPulse API client — calls the real FastAPI backend.
 *
 * FIXED:
 *  - Added getDashboardStats() → GET /dashboard/stats
 *  - Added getAlertStats()    → GET /alerts/stats
 *  - All routes match the FastAPI router prefixes registered in app.py
 */

import type {
  Alert,
  DashboardData,
  LogEntry,
  MonitoringStatus,
  NetworkInfo,
  RogueAccessData,
  SSLStripData,
  Statistics,
} from './types';
const DEFAULT_BASE_URL = 'http://localhost:5000';
const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string) || DEFAULT_BASE_URL;

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return (await res.json()) as T;
}

function withTimeout(ms: number): Promise<never> {
  return new Promise((_, reject) => setTimeout(() => reject(new Error('timeout')), ms));
}

async function fetchApi<T>(path: string): Promise<T> {
  return await Promise.race([apiFetch<T>(path), withTimeout(6000)]);
}

// Stores for real live data trends
let realPacketHistory: number[] = Array.from({ length: 20 }, () => 0);
let prevPacketRate = 0;
let prevAlertsCount = 0;
let prevCriticalCount = 0;

/** Dashboard stats from GET /dashboard/stats (system + security metrics). */
export interface DashboardStats {
  status: 'success' | 'error';
  system_metrics: {
    cpu_percent: number;
    memory_percent: number;
    disk_percent: number;
    uptime: number;
  };
  security_metrics: {
    alerts_24h: number;
    traffic_1h: number;
    unique_ips: number;
    threat_level: 'LOW' | 'MEDIUM' | 'HIGH';
    packet_count: number;
    packet_rate: number;
  };
  detector_status: Record<string, boolean>;
}

/** Alert statistics from GET /alerts/stats. */
export interface AlertStats {
  status: 'success' | 'error';
  severity_stats: Record<string, number>;
  trend_data: { date: string; count: number }[];
  top_attacks: { type: string; count: number }[];
}

export const api = {
  async getStatus(): Promise<MonitoringStatus> {
    return fetchApi('/api/status');
  },

  async getAlerts(): Promise<Alert[]> {
    return fetchApi('/api/alerts');
  },

  async getNetwork(): Promise<NetworkInfo> {
    return fetchApi('/api/network');
  },

  async getStatistics(): Promise<Statistics> {
    return fetchApi('/api/statistics');
  },

  async getLogs(): Promise<LogEntry[]> {
    return fetchApi('/api/logs');
  },

  async getRogueAccess(): Promise<RogueAccessData> {
    return fetchApi('/api/rogue');
  },

  async getSSLStrip(): Promise<SSLStripData> {
    return fetchApi('/api/ssl');
  },

  /** GET /dashboard/stats — system + security metrics from live sources. */
  async getDashboardStats(): Promise<DashboardStats | null> {
    try {
      return await apiFetch<DashboardStats>('/dashboard/stats');
    } catch {
      return null;
    }
  },

  /** GET /alerts/stats — severity counts, daily trends, top attack types. */
  async getAlertStats(): Promise<AlertStats | null> {
    try {
      return await apiFetch<AlertStats>('/alerts/stats');
    } catch {
      return null;
    }
  },

  async start(): Promise<void> {
    await apiFetch('/api/start', { method: 'POST' });
  },

  async stop(): Promise<void> {
    await apiFetch('/api/stop', { method: 'POST' });
  },

  async scan(): Promise<void> {
    await apiFetch('/api/scan', { method: 'POST' });
  },

  async getAll(): Promise<DashboardData> {
    const [status, alerts, network, statistics, logs, rogueAccess, sslStrip] = await Promise.all([
      this.getStatus(),
      this.getAlerts(),
      this.getNetwork(),
      this.getStatistics(),
      this.getLogs(),
      this.getRogueAccess(),
      this.getSSLStrip(),
    ]);

    let packetHistory: number[];
    let trends: { activeAlerts: number; packetRate: number; critical: number };

    // Percentage-change trends from backend responses, capped at ±99.
    realPacketHistory = [...realPacketHistory.slice(1), network.packet_rate || network.packet_count || 0];
    packetHistory = realPacketHistory;

    const currentCritical = alerts.filter((a) => a.details?.severity === 'critical').length;

    const pctChange = (current: number, prev: number): number => {
      if (prev === 0) return 0;
      return Math.max(-99, Math.min(99, Math.round(((current - prev) / prev) * 100)));
    };

    trends = {
      activeAlerts: pctChange(alerts.length, prevAlertsCount),
      packetRate: pctChange(network.packet_rate || 0, prevPacketRate),
      critical: pctChange(currentCritical, prevCriticalCount),
    };

    prevAlertsCount = alerts.length;
    prevPacketRate = network.packet_rate || 0;
    prevCriticalCount = currentCritical;

    return {
      status,
      alerts,
      network,
      statistics,
      logs,
      rogueAccess,
      sslStrip,
      packetHistory,
      trends,
      lastUpdated: Date.now(),
      online: true,
    };
  },
};

export const config = { baseUrl: BASE_URL };
