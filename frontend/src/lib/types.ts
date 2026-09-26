// Core data types for ShadowPulse — mirrors the FastAPI backend API shapes.

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type DetectorKey =
  | 'arp_spoof'
  | 'dns_spoof'
  | 'rogue_access'
  | 'ssl_strip'
  | 'http_inject'
  | 'icmp_redirect'
  | 'dhcp_spoof';

export interface AlertDetails {
  severity: Severity;
  description?: string;
  ssid?: string;
  ap1_bssid?: string;
  ap2_bssid?: string;
  [k: string]: unknown;
}

export interface Alert {
  id: string;
  timestamp: string;
  detector: DetectorKey;
  alert_type: string;
  details: AlertDetails;
}

export interface DeviceInfo {
  ip: string;
  mac: string;
  vendor: string;
  hostname?: string;
  is_gateway?: boolean;
  suspicious?: boolean;
}

export interface NetworkInfo {
  gateway: string;
  interface: string;
  packet_count: number;
  packet_rate: number;
  devices: DeviceInfo[];
}

export interface DetectorStat {
  detector: DetectorKey;
  count: number;
  last_seen?: string;
}

export interface Statistics {
  by_detector: DetectorStat[];
  by_severity: Record<Severity, number>;
  over_time: { time: string; count: number }[];
  heatmap?: HeatmapCell[];
  top_devices?: { ip: string; hostname: string; count: number; suspicious: boolean }[];
  week_comparison?: { day: string; thisWeek: number; lastWeek: number }[];
  detector_health?: { detector: DetectorKey; uptime: number; detections_today: number }[];
  daily_volume?: { day: string; count: number }[];
  threat_score?: number;
}

export interface HeatmapCell {
  day: string;
  hour: number;
  count: number;
}

export interface LogEntry {
  id: string;
  timestamp: string;
  detector: DetectorKey;
  alert_type: string;
  severity: Severity;
  message: string;
}

export interface MonitoringStatus {
  monitoring: boolean;
  interface: string;
  local_ip?: string;
  network_range?: string;
  started_at?: string;
  uptime_seconds?: number;
  detectors_enabled: Partial<Record<DetectorKey, boolean>>;
  detector_status?: Partial<Record<DetectorKey, {
    status: string;
    capability?: 'active' | 'limited' | 'unavailable';
    limitation?: string | null;
  }>>;
}

export interface AuthorizedAP {
  ssid: string;
  bssid: string;
  band?: string;
}

export interface NearbyAP {
  bssid: string;
  ssid: string;
  channel: number;
  rssi: number;
  encryption: string;
  hidden?: boolean;
  authorized?: boolean;
  flags: string[];
}

export interface RogueAccessData {
  authorized_aps: AuthorizedAP[];
  nearby_aps: NearbyAP[];
}

export interface SSLSession {
  id: string;
  host: string;
  ip: string;
  status: 'secure' | 'downgraded' | 'stripped' | 'redirect';
  has_hsts: boolean;
  timestamp: string;
  details?: string;
}

export interface SSLStripData {
  sessions: SSLSession[];
  warnings: { host: string; type: string; message: string; severity: Severity }[];
}

export type HealthState = 'secure' | 'monitoring' | 'under_attack' | 'monitoring_off' | 'offline';

export interface DashboardData {
  status: MonitoringStatus;
  alerts: Alert[];
  network: NetworkInfo;
  statistics: Statistics;
  logs: LogEntry[];
  rogueAccess: RogueAccessData;
  sslStrip: SSLStripData;
  packetHistory: number[];
  trends: { activeAlerts: number; packetRate: number; critical: number };
  lastUpdated: number;
  online: boolean;
}
