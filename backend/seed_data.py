"""Seed sample data into the shadowpulse database for testing."""
import sqlite3
import json
import random
import datetime

conn = sqlite3.connect('shadowpulse.db')
c = conn.cursor()

# Ensure tables exist
c.executescript('''
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        detector_type TEXT NOT NULL,
        severity TEXT NOT NULL,
        source_ip TEXT,
        target_ip TEXT,
        description TEXT,
        details TEXT,
        status TEXT DEFAULT 'new',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        ip_address TEXT UNIQUE NOT NULL,
        mac_address TEXT,
        hostname TEXT,
        vendor TEXT,
        device_type TEXT,
        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
        is_trusted BOOLEAN DEFAULT 0,
        is_rogue BOOLEAN DEFAULT 0,
        risk_score INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS detector_status (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        detector_name TEXT UNIQUE NOT NULL,
        is_enabled BOOLEAN DEFAULT 1,
        status TEXT DEFAULT 'running',
        last_update DATETIME DEFAULT CURRENT_TIMESTAMP
    );
''')

# Seed sample alerts
detectors = ['arp_spoof','dhcp_spoofing','dns_spoof','http_injection','icmp_redirect','rogue_access','ssl_strip']
severities = ['critical','high','medium','low']
ips = ['192.168.1.100','192.168.1.101','192.168.1.102','10.0.0.50','10.0.0.99','172.16.0.5']

for i in range(25):
    det = random.choice(detectors)
    sev = random.choice(severities)
    src = random.choice(ips)
    tgt = random.choice(ips)
    ts = (datetime.datetime.utcnow() - datetime.timedelta(minutes=random.randint(1, 1440))).isoformat()
    description = f"{det.replace('_', ' ').title()} detected from {src}"
    c.execute('''
        INSERT INTO alerts (timestamp, detector_type, severity, source_ip, target_ip, description, details)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    ''', (ts, det, sev, src, tgt, description, '{}'))
print('Seeded 25 alerts')

# Seed devices
devices_data = [
    ('192.168.1.1', '00:1A:2B:3C:4D:5E', 'router-gw', 'TP-Link', 'gateway', 1, 0, 0),
    ('192.168.1.100', 'AA:BB:CC:DD:EE:01', 'MacBook-Pro', 'Apple Inc.', 'workstation', 1, 0, 0),
    ('192.168.1.101', 'AA:BB:CC:DD:EE:02', 'iPhone-13', 'Samsung Elec.', 'mobile', 1, 0, 0),
    ('192.168.1.102', 'AA:BB:CC:DD:EE:03', 'DESKTOP-A1B2', 'Intel Corp.', 'workstation', 1, 0, 0),
    ('192.168.1.103', 'AA:BB:CC:DD:EE:04', 'unknown-device', 'Unknown', 'unknown', 0, 1, 8),
    ('192.168.1.104', 'AA:BB:CC:DD:EE:05', 'IoT-Cam-01', 'Raspberry Pi', 'iot', 1, 0, 2),
    ('192.168.1.105', 'AA:BB:CC:DD:EE:06', 'esp-8266-x', 'Espressif', 'iot', 0, 1, 6),
]
for d in devices_data:
    c.execute('''INSERT OR IGNORE INTO devices (ip_address, mac_address, hostname, vendor, device_type, is_trusted, is_rogue, risk_score)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)''', d)
print('Seeded', len(devices_data), 'devices')

# Seed detector status
for det in ['arp_spoof','dhcp_spoofing','dns_spoof','http_injection','icmp_redirect','rogue_access','ssl_strip']:
    c.execute('''INSERT OR IGNORE INTO detector_status (detector_name, is_enabled, status)
                 VALUES (?, 1, 'running')''', (det,))
print('Seeded detector status')

conn.commit()
conn.close()
print('All seed data inserted successfully!')
