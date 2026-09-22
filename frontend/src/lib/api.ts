/**
 * frontend/src/lib/api.ts
 * ShadowPulse API client — calls the real FastAPI backend.
 *
 * FIXED:
 *  - Added getDashboardStats() → GET /dashboard/stats
 *  - Added getAlertStats()    → GET /alerts/stats
 *  - All routes match the FastAPI router prefixes registered in app.py
 *  - Mock fallback still available when VITE_USE_MOCK=true (dev only)
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
import {
  generateAlert,
  generateAlerts,
  generateLogs,
  generateNetwork,
  generateRogueAccess,
  generateSSLStrip,
  generateStatistics,
  generateStatus,
} from './mockData';

const DEFAULT_BASE_URL = 'http://localhost:5000';
const BASE_URL = (import.meta.env.VITE_API_BASE_URL as string) || DEFAULT_BASE_URL;

// Toggle: set to true to always use mock data, false to use the real backend.
const USE_MOCK = (import.meta.env.VITE_USE_MOCK as string) === 'true';

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

async function fetchWithFallback<T>(path: string, mock: () => T): Promise<T> {
  if (USE_MOCK) return mock();
  return await Promise.race([apiFetch<T>(path), withTimeout(6000)]);
}

// Stores for real live data trends
let realPacketHistory: number[] = Array.from({ length: 20 }, () => 0);
let prevPacketRate = 0;
let prevAlertsCount = 0;
let prevCriticalCount = 0;

// In-memory store so mock data persists across polls within a session when USE_MOCK=true.
let mockStatus = generateStatus(true);
let mockAlerts = generateAlerts(12);
let mockNetwork = generateNetwork();
let mockStats = generateStatistics(mockAlerts);
let mockLogs = generateLogs(mockAlerts);
let mockRogue = generateRogueAccess();
let mockSSL = generateSSLStrip();
let mockPacketHistory: number[] = Array.from({ length: 20 }, () => 50 + Math.floor(Math.random() * 750));
let mockPrevTrends = { activeAlerts: 8, packetRate: 500, critical: 2 };

function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

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
    return fetchWithFallback('/api/status', () => mockStatus);
  },

  async getAlerts(): Promise<Alert[]> {
    if (USE_MOCK && mockStatus.monitoring && Math.random() > 0.55) {
      mockAlerts = [generateAlert(), ...mockAlerts].slice(0, 60);
    }
    return fetchWithFallback('/api/alerts', () => mockAlerts);
  },

  async getNetwork(): Promise<NetworkInfo> {
    if (USE_MOCK) mockNetwork = generateNetwork();
    return fetchWithFallback('/api/network', () => mockNetwork);
  },

  async getStatistics(): Promise<Statistics> {
    if (USE_MOCK) mockStats = generateStatistics(mockAlerts);
    return fetchWithFallback('/api/statistics', () => mockStats);
  },

  async getLogs(): Promise<LogEntry[]> {
    if (USE_MOCK) mockLogs = generateLogs(mockAlerts);
    return fetchWithFallback('/api/logs', () => mockLogs);
  },

  async getRogueAccess(): Promise<RogueAccessData> {
    return fetchWithFallback('/api/rogue', () => mockRogue);
  },

  async getSSLStrip(): Promise<SSLStripData> {
    return fetchWithFallback('/api/ssl', () => mockSSL);
  },

  /** GET /dashboard/stats — system + security metrics from live sources. */
  async getDashboardStats(): Promise<DashboardStats | null> {
    if (USE_MOCK) return null;
    try {
      return await apiFetch<DashboardStats>('/dashboard/stats');
    } catch {
      return null;
    }
  },

  /** GET /alerts/stats — severity counts, daily trends, top attack types. */
  async getAlertStats(): Promise<AlertStats | null> {
    if (USE_MOCK) return null;
    try {
      return await apiFetch<AlertStats>('/alerts/stats');
    } catch {
      return null;
    }
  },

  async start(): Promise<void> {
    if (USE_MOCK) {
      mockStatus = { ...mockStatus, monitoring: true, started_at: new Date().toISOString() };
      return;
    }
    await apiFetch('/api/start', { method: 'POST' });
  },

  async stop(): Promise<void> {
    if (USE_MOCK) {
      mockStatus = { ...mockStatus, monitoring: false };
      return;
    }
    await apiFetch('/api/stop', { method: 'POST' });
  },

  async scan(): Promise<void> {
    if (USE_MOCK) {
      mockNetwork = generateNetwork();
      mockRogue = generateRogueAccess();
      return;
    }
    await apiFetch('/api/scan', { method: 'POST' });
  },

  async getAll(): Promise<DashboardData> {
    const [status, alerts, network, statistics, logs] = await Promise.all([
      this.getStatus(),
      this.getAlerts(),
      this.getNetwork(),
      this.getStatistics(),
      this.getLogs(),
    ]);

    let packetHistory: number[];
    let trends: { activeAlerts: number; packetRate: number; critical: number };

    if (USE_MOCK) {
      mockPacketHistory = [...mockPacketHistory.slice(1), network.packet_rate];
      packetHistory = mockPacketHistory;
      trends = {
        activeAlerts: mockPrevTrends.activeAlerts,
        packetRate: mockPrevTrends.packetRate,
        critical: mockPrevTrends.critical,
      };
      mockPrevTrends = {
        activeAlerts: alerts.length,
        packetRate: network.packet_rate,
        critical: alerts.filter((a) => a.details?.severity === 'critical').length,
      };
    } else {
      // Real-data path: percentage-change trends capped at ±99.
      realPacketHistory = [...realPacketHistory.slice(1), network.packet_rate || network.packet_count || 0];
      packetHistory = realPacketHistory;

      const currentCritical = alerts.filter((a) => a.details?.severity === 'critical').length;

      const pctChange = (current: number, prev: number): number => {
        if (prev === 0) return 0;
        return Math.max(-99, Math.min(99, Math.round(((current - prev) / prev) * 100)));
      };

      trends = {
        activeAlerts: pctChange(alerts.length, prevAlertsCount),
        packetRate:   pctChange(network.packet_rate || 0, prevPacketRate),
        critical:     pctChange(currentCritical, prevCriticalCount),
      };

      prevAlertsCount   = alerts.length;
      prevPacketRate    = network.packet_rate || 0;
      prevCriticalCount = currentCritical;
    }

    return {
      status,
      alerts,
      network,
      statistics,
      logs,
      rogueAccess: { authorized_aps: [], nearby_aps: [] },
      sslStrip: { sessions: [], warnings: [] },
      packetHistory,
      trends,
      lastUpdated: Date.now(),
      online: true,
    };
  },
};

export const config = { baseUrl: BASE_URL, useMock: USE_MOCK };
