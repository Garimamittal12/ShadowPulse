import type {
  Alert,
  AlertDetails,
  DetectorKey,
  DeviceInfo,
  LogEntry,
  MonitoringStatus,
  NetworkInfo,
  NearbyAP,
  RogueAccessData,
  SSLSession,
  SSLStripData,
  Severity,
  Statistics,
  HeatmapCell,
} from './types';
import { DETECTORS } from './detectors';

const DETECTOR_KEYS = Object.keys(DETECTORS) as DetectorKey[];

const VENDORS = ['Apple Inc.', 'Cisco Systems', 'Intel Corp.', 'Samsung Elec.', 'TP-Link', 'Netgear', 'Dell Inc.', 'Raspberry Pi', 'Unknown', 'Espressif'];
const HOSTS = ['DESKTOP-A1B2', 'MacBook-Pro', 'iPhone-13', 'android-pixel', 'IoT-Cam-01', 'NAS-Synology', 'printer-hp', 'smart-tv-sam'];
const SSIDS = ['Office WiFi', 'Office WiFi', 'Office-WiFi', 'Office Guest', 'Office WiFi 5G', 'HomeNet', 'FreePublicWiFi'];
const ALERT_TYPES: Record<DetectorKey, string[]> = {
  arp_spoof: ['arp_spoofing_detected', 'duplicate_mac_response'],
  dns_spoof: ['dns_response_mismatch', 'rogue_dns_server'],
  rogue_access: ['evil_twin_detected', 'ssid_impersonation', 'hidden_ssid_found', 'open_network_found'],
  ssl_strip: ['https_downgrade', 'hsts_missing', 'ssl_strip_attempt'],
  http_inject: ['http_content_injection', 'script_injection'],
  icmp_redirect: ['icmp_redirect_received'],
  dhcp_spoof: ['rogue_dhcp_server', 'dhcp_offer_mismatch'],
};
const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

let packetCount = 184320;
let alertCounter = 0;

function rand<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}
function randInt(min: number, max: number): number {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function randMac(): string {
  return Array.from({ length: 6 }, () =>
    randInt(0, 255).toString(16).padStart(2, '0').toUpperCase()
  ).join(':');
}
function randIp(): string {
  return `192.168.1.${randInt(10, 240)}`;
}
function timeAgo(secondsAgo: number): string {
  return new Date(Date.now() - secondsAgo * 1000).toISOString().replace('T', ' ').slice(0, 19);
}

export function generateAlert(detector?: DetectorKey): Alert {
  const det = detector ?? rand(DETECTOR_KEYS);
  const alertType = rand(ALERT_TYPES[det]);
  const severity = rand(SEVERITIES);
  const details: AlertDetails = { severity, description: DETECTORS[det].label + ' detected' };
  if (det === 'rogue_access') {
    details.ssid = rand(SSIDS);
    details.ap1_bssid = randMac();
    details.ap2_bssid = randMac();
    details.description = 'Potential Evil Twin Attack';
  }
  if (det === 'dns_spoof') {
    details.domain = rand(['google.com', 'bank.example.com', 'login.example.com', 'github.com']);
  }
  if (det === 'arp_spoof') {
    details.attacker_mac = randMac();
    details.victim_ip = randIp();
  }
  if (det === 'ssl_strip') {
    details.host = rand(['login.example.com', 'mail.example.com', 'bank.example.com']);
  }
  alertCounter += 1;
  return {
    id: `alert-${alertCounter}`,
    timestamp: timeAgo(randInt(1, 600)),
    detector: det,
    alert_type: alertType,
    details,
  };
}

export function generateAlerts(count: number): Alert[] {
  return Array.from({ length: count }, () => generateAlert()).sort(
    (a, b) => b.timestamp.localeCompare(a.timestamp)
  );
}

export function generateDevices(): DeviceInfo[] {
  const count = randInt(6, 12);
  const devices: DeviceInfo[] = [
    { ip: '192.168.1.1', mac: '00:1A:2B:3C:4D:5E', vendor: 'TP-Link', hostname: 'router-gw', is_gateway: true },
  { ip: '192.168.1.100', mac: randMac(), vendor: 'Apple Inc.', hostname: 'MacBook-Pro' },
  { ip: '192.168.1.101', mac: randMac(), vendor: 'Samsung Elec.', hostname: 'iPhone-13' },
  { ip: '192.168.1.102', mac: randMac(), vendor: 'Intel Corp.', hostname: 'DESKTOP-A1B2' },
  { ip: '192.168.1.103', mac: randMac(), vendor: 'Unknown', hostname: 'unknown-device', suspicious: true },
  { ip: '192.168.1.104', mac: randMac(), vendor: 'Raspberry Pi', hostname: 'IoT-Cam-01' },
  { ip: '192.168.1.105', mac: randMac(), vendor: 'Unknown', hostname: 'esp-8266-x', suspicious: true },
    { ip: '192.168.1.106', mac: randMac(), vendor: 'Netgear', hostname: 'NAS-Synology' },
  { ip: '192.168.1.107', mac: randMac(), vendor: 'Dell Inc.', hostname: 'printer-hp' },
    { ip: '192.168.1.108', mac: randMac(), vendor: 'Espressif', hostname: 'smart-bulb-1' },
  ];
  return devices.slice(0, count);
}

export function generateNetwork(): NetworkInfo {
  packetCount += randInt(50, 500);
  return {
    gateway: '192.168.1.1',
    interface: 'eth0',
    packet_count: packetCount,
    packet_rate: randInt(80, 1200),
    devices: generateDevices(),
  };
}

export function generateStatus(monitoring = true): MonitoringStatus {
  return {
    monitoring,
    interface: 'eth0',
    started_at: monitoring ? timeAgo(randInt(60, 7200)) : undefined,
    uptime_seconds: monitoring ? randInt(60, 7200) : 0,
    detectors_enabled: DETECTOR_KEYS.reduce(
      (acc, k) => ({ ...acc, [k]: true }),
      {} as Record<DetectorKey, boolean>
    ),
  };
}

export function generateStatistics(alerts: Alert[]): Statistics {
  const byDetector = DETECTOR_KEYS.map((d) => ({
    detector: d,
    count: alerts.filter((a) => a.detector === d).length || randInt(0, 8),
    last_seen: alerts.find((a) => a.detector === d)?.timestamp,
  }));
  const bySeverity = SEVERITIES.reduce(
    (acc, s) => ({ ...acc, [s]: alerts.filter((a) => a.details.severity === s).length || randInt(0, 6) }),
    {} as Record<Severity, number>
  );
  const overTime = Array.from({ length: 24 }, (_, i) => {
    const h = `${String(i).padStart(2, '0')}:00`;
    return { time: h, count: randInt(0, 14) };
  });
  const days = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
  const heatmap: HeatmapCell[] = [];
  for (const day of days) {
    for (let h = 0; h < 24; h++) {
      const count = h >= 9 && h <= 18 ? randInt(0, 8) : randInt(0, 4);
      heatmap.push({ day, hour: h, count });
    }
  }
  const top_devices = (alerts.length > 0 ? alerts.slice(0, 8) : generateAlerts(8)).map((a, i) => ({
    ip: (a.details.victim_ip as string) ?? randIp(),
    hostname: HOSTS[i % HOSTS.length],
    count: randInt(1, 12),
    suspicious: i % 4 === 3,
  })).sort((a, b) => b.count - a.count).slice(0, 8);
  const week_comparison = days.map((day) => ({
    day,
    thisWeek: randInt(2, 18),
    lastWeek: randInt(2, 18),
  }));
  const detector_health = DETECTOR_KEYS.map((d) => ({
    detector: d,
    uptime: randInt(92, 100),
    detections_today: randInt(0, 9),
  }));
  const daily_volume = days.map((day) => ({ day, count: randInt(0, 20) }));
  return { by_detector: byDetector, by_severity: bySeverity, over_time: overTime, heatmap, top_devices, week_comparison, detector_health, daily_volume };
}

export function generateLogs(alerts: Alert[]): LogEntry[] {
  return alerts.map((a) => ({
    id: a.id,
    timestamp: a.timestamp,
    detector: a.detector,
    alert_type: a.alert_type,
    severity: a.details.severity,
    message: a.details.description ?? `${DETECTORS[a.detector].label} — ${a.alert_type}`,
  }));
}

export function generateRogueAccess(): RogueAccessData {
  const authorized = [
    { ssid: 'Office WiFi', bssid: '00:1A:2B:3C:4D:5E', band: '2.4GHz' },
    { ssid: 'Office WiFi 5G', bssid: '00:1A:2B:3C:4D:5F', band: '5GHz' },
  ];
  const nearby: NearbyAP[] = [
    { bssid: '00:1A:2B:3C:4D:5E', ssid: 'Office WiFi', channel: 6, rssi: -42, encryption: 'WPA2-PSK', authorized: true, flags: [] },
    { bssid: '00:1A:2B:3C:4D:5F', ssid: 'Office WiFi 5G', channel: 36, rssi: -55, encryption: 'WPA3-SAE', authorized: true, flags: [] },
    { bssid: randMac(), ssid: 'Office WiFi', channel: 11, rssi: -68, encryption: 'Open', authorized: false, flags: ['Evil Twin', 'Open Network'] },
    { bssid: randMac(), ssid: 'Office-WiFi', channel: 1, rssi: -74, encryption: 'WPA2-PSK', authorized: false, flags: ['SSID Impersonation'] },
    { bssid: randMac(), ssid: '', channel: 6, rssi: -80, encryption: 'WPA2-PSK', hidden: true, authorized: false, flags: ['Hidden SSID'] },
    { bssid: randMac(), ssid: 'FreePublicWiFi', channel: 11, rssi: -85, encryption: 'Open', authorized: false, flags: ['Open Network'] },
  ];
  return { authorized_aps: authorized, nearby_aps: nearby };
}

export function generateSSLStrip(): SSLStripData {
  const sessions: SSLSession[] = [
    { id: 's1', host: 'login.example.com', ip: '93.184.216.34', status: 'secure', has_hsts: true, timestamp: timeAgo(120) },
    { id: 's2', host: 'mail.example.com', ip: '93.184.216.35', status: 'downgraded', has_hsts: false, timestamp: timeAgo(90), details: 'HTTPS downgraded to HTTP at redirect' },
    { id: 's3', host: 'bank.example.com', ip: '93.184.216.36', status: 'stripped', has_hsts: false, timestamp: timeAgo(60), details: 'SSL stripped — HSTS absent' },
    { id: 's4', host: 'shop.example.com', ip: '93.184.216.37', status: 'redirect', has_hsts: true, timestamp: timeAgo(30), details: 'Unexpected 302 redirect to HTTP' },
    { id: 's5', host: 'api.example.com', ip: '93.184.216.38', status: 'secure', has_hsts: true, timestamp: timeAgo(15) },
  ];
  const warnings = sessions
    .filter((s) => s.status !== 'secure')
    .map((s) => ({
      host: s.host,
      type: s.status,
      message: s.details ?? 'Connection may not be secure',
      severity: (s.status === 'stripped' ? 'critical' : 'high') as Severity,
    }));
  return { sessions, warnings };
}
