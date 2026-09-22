import sqlite3
import threading
import json
from datetime import datetime, timedelta
from contextlib import contextmanager
from typing import List, Dict, Any, Optional, Tuple
from pathlib import Path

class DatabaseManager:
    """Database management for SHADOWPULSE"""
    
    def __init__(self, db_path: str = 'shadowpulse.db'):
        self.db_path = db_path
        self.lock = threading.RLock()
        # Configure WAL mode once at startup (not per-connection).
        with self.get_connection() as conn:
            conn.execute('PRAGMA journal_mode = WAL')
            conn.execute('PRAGMA synchronous = NORMAL')
            conn.execute('PRAGMA busy_timeout = 30000')
        self._init_database()
    
    def _init_database(self):
        """Initialize database with required tables"""
        with self.get_connection() as conn:
            self._create_tables(conn)
            self._create_indexes(conn)
    
    def _create_tables(self, conn: sqlite3.Connection):
        """Create all required database tables"""
        tables = {
            'alerts': '''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    detector_type TEXT NOT NULL,
                    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                    source_ip TEXT,
                    target_ip TEXT,
                    source_mac TEXT,
                    target_mac TEXT,
                    protocol TEXT,
                    description TEXT NOT NULL,
                    details TEXT,
                    status TEXT DEFAULT 'new' CHECK (status IN ('new', 'investigating', 'resolved', 'false_positive')),
                    notes TEXT,
                    resolved_by TEXT,
                    resolved_at DATETIME,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'network_logs': '''
                CREATE TABLE IF NOT EXISTS network_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    source_ip TEXT NOT NULL,
                    destination_ip TEXT NOT NULL,
                    source_port INTEGER,
                    destination_port INTEGER,
                    protocol TEXT NOT NULL,
                    packet_size INTEGER,
                    flags TEXT,
                    payload_hash TEXT,
                    payload_snippet TEXT,
                    session_id TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'devices': '''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT UNIQUE NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    operating_system TEXT,
                    open_ports TEXT,
                    services TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_trusted BOOLEAN DEFAULT 0,
                    is_rogue BOOLEAN DEFAULT 0,
                    risk_score INTEGER DEFAULT 0,
                    reputation_score INTEGER DEFAULT 50,
                    geolocation TEXT,
                    notes TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'detector_status': '''
                CREATE TABLE IF NOT EXISTS detector_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    detector_name TEXT UNIQUE NOT NULL,
                    is_enabled BOOLEAN DEFAULT 1,
                    status TEXT DEFAULT 'stopped' CHECK (status IN ('running', 'stopped', 'error')),
                    last_update DATETIME DEFAULT CURRENT_TIMESTAMP,
                    config TEXT,
                    performance_stats TEXT,
                    error_message TEXT,
                    restart_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'system_config': '''
                CREATE TABLE IF NOT EXISTS system_config (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    config_key TEXT UNIQUE NOT NULL,
                    config_value TEXT,
                    config_type TEXT DEFAULT 'string',
                    description TEXT,
                    is_sensitive BOOLEAN DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'scheduled_reports': '''
                CREATE TABLE IF NOT EXISTS scheduled_reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    schedule_cron TEXT NOT NULL,
                    recipients TEXT,
                    format TEXT DEFAULT 'json',
                    filters TEXT,
                    is_active BOOLEAN DEFAULT 1,
                    next_run DATETIME,
                    last_run DATETIME,
                    run_count INTEGER DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'threat_intelligence': '''
                CREATE TABLE IF NOT EXISTS threat_intelligence (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    indicator_type TEXT NOT NULL CHECK (indicator_type IN ('ip', 'domain', 'hash', 'url')),
                    indicator_value TEXT NOT NULL,
                    threat_type TEXT,
                    severity TEXT CHECK (severity IN ('low', 'medium', 'high', 'critical')),
                    confidence INTEGER DEFAULT 50,
                    source TEXT,
                    description TEXT,
                    tags TEXT,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''',
            
            'packet_captures': '''
                CREATE TABLE IF NOT EXISTS packet_captures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    file_path TEXT NOT NULL,
                    file_size INTEGER,
                    packet_count INTEGER,
                    start_time DATETIME,
                    end_time DATETIME,
                    filters TEXT,
                    trigger_event TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            '''
        }
        
        cursor = conn.cursor()
        for table_name, table_sql in tables.items():
            cursor.execute(table_sql)
        conn.commit()
    
    def _create_indexes(self, conn: sqlite3.Connection):
        """Create database indexes for performance"""
        indexes = [
            'CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON alerts(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_detector ON alerts(detector_type)',
            'CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status)',
            'CREATE INDEX IF NOT EXISTS idx_network_logs_timestamp ON network_logs(timestamp)',
            'CREATE INDEX IF NOT EXISTS idx_network_logs_source_ip ON network_logs(source_ip)',
            'CREATE INDEX IF NOT EXISTS idx_network_logs_dest_ip ON network_logs(destination_ip)',
            'CREATE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip_address)',
            'CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac_address)',
            'CREATE INDEX IF NOT EXISTS idx_devices_last_seen ON devices(last_seen)',
            'CREATE INDEX IF NOT EXISTS idx_threat_intel_indicator ON threat_intelligence(indicator_value)',
            'CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intelligence(indicator_type)'
        ]
        
        cursor = conn.cursor()
        for index_sql in indexes:
            cursor.execute(index_sql)
        conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Get database connection with automatic cleanup.

        WAL mode and busy_timeout are configured once in __init__ to avoid
        per-connection PRAGMA churn (which can cause locking contention on
        Windows). Each connection still sets foreign_keys = ON locally.
        """
        conn = sqlite3.connect(self.db_path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute('PRAGMA foreign_keys = ON')
        try:
            yield conn
        finally:
            conn.close()
    
    def insert_alert(self, detector_type: str, severity: str, description: str, 
                    source_ip: str = None, target_ip: str = None, **kwargs) -> int:
        """Insert new security alert"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO alerts (detector_type, severity, source_ip, target_ip, 
                                  source_mac, target_mac, protocol, description, details)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                detector_type, severity, source_ip, target_ip,
                kwargs.get('source_mac'), kwargs.get('target_mac'),
                kwargs.get('protocol'), description, json.dumps(kwargs.get('details', {}))
            ))
            conn.commit()
            return cursor.lastrowid
    
    def insert_network_log(self, source_ip: str, dest_ip: str, protocol: str, **kwargs) -> int:
        """Insert network traffic log entry"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO network_logs (source_ip, destination_ip, source_port, 
                                        destination_port, protocol, packet_size, flags, 
                                        payload_hash, payload_snippet, session_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                source_ip, dest_ip, kwargs.get('source_port'), kwargs.get('dest_port'),
                protocol, kwargs.get('packet_size'), kwargs.get('flags'),
                kwargs.get('payload_hash'), kwargs.get('payload_snippet'),
                kwargs.get('session_id')
            ))
            conn.commit()
            return cursor.lastrowid
    
    def upsert_device(self, ip_address: str, **kwargs) -> int:
        """Insert or update device information"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Try to get existing device
            cursor.execute('SELECT id FROM devices WHERE ip_address = ?', (ip_address,))
            existing = cursor.fetchone()
            
            if existing:
                # Update existing device
                cursor.execute('''
                    UPDATE devices SET 
                        mac_address = COALESCE(?, mac_address),
                        hostname = COALESCE(?, hostname),
                        vendor = COALESCE(?, vendor),
                        device_type = COALESCE(?, device_type),
                        operating_system = COALESCE(?, operating_system),
                        open_ports = ?,
                        services = ?,
                        last_seen = CURRENT_TIMESTAMP,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE ip_address = ?
                ''', (
                    kwargs.get('mac_address'), kwargs.get('hostname'),
                    kwargs.get('vendor'), kwargs.get('device_type'),
                    kwargs.get('operating_system'),
                    json.dumps(kwargs.get('open_ports', [])),
                    json.dumps(kwargs.get('services', [])),
                    ip_address
                ))
                conn.commit()
                return existing['id']
            else:
                # Insert new device
                cursor.execute('''
                    INSERT INTO devices (ip_address, mac_address, hostname, vendor, 
                                       device_type, operating_system, open_ports, services)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    ip_address, kwargs.get('mac_address'), kwargs.get('hostname'),
                    kwargs.get('vendor'), kwargs.get('device_type'),
                    kwargs.get('operating_system'),
                    json.dumps(kwargs.get('open_ports', [])),
                    json.dumps(kwargs.get('services', []))
                ))
                conn.commit()
                return cursor.lastrowid
    
    def get_alerts(self, limit: int = 100, severity: str = None, 
                  detector: str = None, status: str = None) -> List[Dict]:
        """Get security alerts with filtering"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            where_clauses = []
            params = []
            
            if severity:
                where_clauses.append('severity = ?')
                params.append(severity)
            
            if detector:
                where_clauses.append('detector_type = ?')
                params.append(detector)
            
            if status:
                where_clauses.append('status = ?')
                params.append(status)
            
            where_sql = ' AND '.join(where_clauses) if where_clauses else '1=1'
            
            cursor.execute(f'''
                SELECT * FROM alerts 
                WHERE {where_sql}
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', params + [limit])
            
            return [dict(row) for row in cursor.fetchall()]
    
    def get_devices(self, include_inactive: bool = False) -> List[Dict]:
        """Get network devices"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            if include_inactive:
                cursor.execute('''
                    SELECT * FROM devices
                    WHERE lower(COALESCE(mac_address, '')) NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                    ORDER BY last_seen DESC
                ''')
            else:
                cursor.execute('''
                    SELECT * FROM devices 
                    WHERE last_seen > datetime('now', '-24 hours')
                      AND lower(COALESCE(mac_address, '')) NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                    ORDER BY last_seen DESC
                ''')
            
            return [dict(row) for row in cursor.fetchall()]
    
    def cleanup_old_logs(self, retention_days: int = 7):
        """Clean up old network logs"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM network_logs 
                WHERE created_at < datetime('now', '-' || ? || ' days')
            ''', (retention_days,))
            conn.commit()
            return cursor.rowcount
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get database statistics"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            stats = {}
            
            # Count tables
            tables = ['alerts', 'network_logs', 'devices', 'threat_intelligence']
            for table in tables:
                cursor.execute(f'SELECT COUNT(*) FROM {table}')
                stats[f'{table}_count'] = cursor.fetchone()[0]
            
            # Database size
            cursor.execute("SELECT page_count * page_size as size FROM pragma_page_count(), pragma_page_size()")
            stats['database_size_bytes'] = cursor.fetchone()[0]
            
            # Recent activity (last 24 hours)
            cursor.execute('''
                SELECT COUNT(*) FROM alerts 
                WHERE timestamp > datetime('now', '-24 hours')
            ''')
            stats['alerts_24h'] = cursor.fetchone()[0]
            
            cursor.execute('''
                SELECT COUNT(*) FROM network_logs 
                WHERE timestamp > datetime('now', '-1 hour')
            ''')
            stats['network_logs_1h'] = cursor.fetchone()[0]
            
            return stats

def get_db_connection() -> sqlite3.Connection:
    """Get a raw SQLite connection using the centralized DB path from config.
    FIXED: no longer hardcodes 'shadowpulse.db'; reads path from utils.config.
    Caller is responsible for calling conn.close().
    """
    try:
        from utils.config import get_config
        db_path = get_config().get('DATABASE', 'path', 'shadowpulse.db')
    except Exception:
        db_path = 'shadowpulse.db'
    return sqlite3.connect(db_path, timeout=30.0)

# Global database manager instance
_db_manager = None

def get_db_manager() -> DatabaseManager:
    """Get global database manager instance"""
    global _db_manager
    if _db_manager is None:
        _db_manager = DatabaseManager()
    return _db_manager
