"""
Consolidated API blueprint for ShadowPulse.

All `/api/*` endpoints return data from LIVE sources only:
    - MonitoringManager (runtime state, packet counters, detector health)
    - NetworkMonitor (discovered devices)
    - AlertManager / SQLite (alerts, logs, statistics)
    - Detector instances (rogue AP, SSL strip)

There are NO random values, NO hardcoded devices, and NO fabricated metrics.
"""

from flask import Blueprint, jsonify, request, current_app
from datetime import datetime, timedelta
import json
import sqlite3

from utils.database import get_db_manager, get_db_connection

api_bp = Blueprint('api', __name__, url_prefix='/api')

DETECTOR_KEYS = [
    'arp_spoof', 'dhcp_spoof', 'dns_spoof', 'http_inject',
    'icmp_redirect', 'rogue_access', 'ssl_strip'
]

SEVERITIES = ['critical', 'high', 'medium', 'low', 'info']


def _normalize_detector(detector: str) -> str:
    """Map DB/detector names to frontend DetectorKey."""
    mapping = {
        'arp_spoof': 'arp_spoof',
        'dhcp_spoofing': 'dhcp_spoof',
        'dhcp_spoof': 'dhcp_spoof',
        'dns_spoof': 'dns_spoof',
        'http_injection': 'http_inject',
        'http_inject': 'http_inject',
        'icmp_redirect': 'icmp_redirect',
        'rogue_access': 'rogue_access',
        'ssl_strip': 'ssl_strip',
    }
    return mapping.get(detector, detector)


def _normalize_severity(sev: str) -> str:
    if sev and sev.lower() in SEVERITIES:
        return sev.lower()
    return 'medium'


def _get_manager():
    """Return the global MonitoringManager (or None if not wired)."""
    try:
        # Prefer the app-bound MonitoringManager when running inside Flask
        app_mm = getattr(current_app, "monitoring_manager", None)
        if app_mm is not None:
            return app_mm
    except Exception:
        # current_app may not be available outside request context
        pass
    try:
        from utils.engine import get_monitoring_manager
        return get_monitoring_manager()
    except Exception:
        try:
            # Last-resort: try importing app directly
            from app import monitoring_manager
            return monitoring_manager
        except Exception:
            return None


def _parse_details(details_raw) -> dict:
    details = {}
    if details_raw:
        try:
            extra = json.loads(details_raw) if isinstance(details_raw, str) else details_raw
            if isinstance(extra, dict):
                details = extra
        except (json.JSONDecodeError, TypeError):
            pass
    return details


def _extract_alert_type(detector: str, details: dict) -> str:
    """Preserve the real alert_type from details, falling back to detector_detected."""
    alert_type = details.get("alert_type")
    if alert_type and isinstance(alert_type, str):
        return alert_type
    return f"{detector}_detected"


# ---------------------------------------------------------------------------
# GET /api/status
# ---------------------------------------------------------------------------
@api_bp.route('/status', methods=['GET'])
def get_status():
    """Return live monitoring status from the real engine."""
    manager = _get_manager()
    if manager is not None:
        return jsonify(manager.status_dict())

    # Engine not wired — never fabricate data.
    return jsonify({
        'monitoring': False,
        'interface': None,
        'started_at': None,
        'uptime_seconds': 0,
        'packet_count': 0,
        'packets_per_second': 0.0,
        'detectors_enabled': {},
        'detector_status': {},
        'thread_status': {},
    })


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------
@api_bp.route('/alerts', methods=['GET'])
def get_alerts():
    """Return live alerts from SQLite, newest first."""
    limit = request.args.get('limit', 100, type=int)
    alerts = []
    try:
        conn = get_db_connection()
        conn.row_factory = __import__('sqlite3').Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, detector_type, severity, source_ip, target_ip, "
            "source_mac, target_mac, protocol, description, details "
            "FROM alerts ORDER BY timestamp DESC LIMIT ?", (limit,)
        )
        rows = cursor.fetchall()
        conn.close()
    except Exception:
        rows = []

    for row in rows:
        detector = _normalize_detector(row['detector_type'])
        severity = _normalize_severity(row['severity'])
        details = _parse_details(row['details'])
        details.setdefault('severity', severity)
        details.setdefault('description', row['description'] or '')

        alerts.append({
            'id': str(row['id']),
            'timestamp': str(row['timestamp']),
            'detector': detector,
            'alert_type': _extract_alert_type(detector, details),
            'severity': severity,
            'source_ip': row['source_ip'],
            'target_ip': row['target_ip'],
            'source_mac': row['source_mac'],
            'target_mac': row['target_mac'],
            'protocol': row['protocol'],
            'description': row['description'],
            'details': details,
        })

    return jsonify(alerts)


# ---------------------------------------------------------------------------
# GET /api/network
# ---------------------------------------------------------------------------
@api_bp.route('/network', methods=['GET'])
def get_network():
    """Return discovered devices from NetworkMonitor (no fabricated devices)."""
    manager = _get_manager()
    if manager is not None:
        return jsonify(manager.network_data())

    # No engine — return empty (no fake data).
    return jsonify({
        'gateway': None,
        'interface': None,
        'packet_count': 0,
        'packet_rate': 0.0,
        'devices': [],
    })


# ---------------------------------------------------------------------------
# GET /api/statistics
# ---------------------------------------------------------------------------
@api_bp.route('/statistics', methods=['GET'])
def get_statistics():
    """Return statistics computed from SQLite + runtime metrics (no random)."""
    manager = _get_manager()
    if manager is not None:
        return jsonify(manager.statistics_data())

    # No engine — return zeroed, real structure.
    return jsonify({
        'by_detector': [{'detector': k, 'count': 0} for k in DETECTOR_KEYS],
        'by_severity': {s: 0 for s in SEVERITIES},
        'over_time': [{'time': f'{h:02d}:00', 'count': 0} for h in range(24)],
        'heatmap': [],
        'top_devices': [],
        'week_comparison': [],
        'detector_health': [{'detector': k, 'uptime': 0.0, 'detections_today': 0} for k in DETECTOR_KEYS],
        'daily_volume': [],
        'threat_score': 0,
        'packet_count': 0,
        'packet_rate': 0.0,
        'total_alerts': 0,
        'devices_online': 0,
        'alerts_24h': 0,
        'network_logs_1h': 0,
    })


# ---------------------------------------------------------------------------
# GET /api/logs
# ---------------------------------------------------------------------------
@api_bp.route('/logs', methods=['GET'])
def get_logs():
    """Return real log entries from SQLite."""
    limit = request.args.get('limit', 200, type=int)
    logs = []
    try:
        db = get_db_manager()
        rows = db.get_alerts(limit=limit)
    except Exception:
        rows = []

    for row in rows:
        # DatabaseManager returns dict rows; fall back to row[...] for compatibility
        detector_raw = row.get('detector_type') if isinstance(row, dict) else row['detector_type']
        detector = _normalize_detector(detector_raw)
        severity_raw = row.get('severity') if isinstance(row, dict) else row['severity']
        severity = _normalize_severity(severity_raw)
        details_raw = row.get('details') if isinstance(row, dict) else row['details']
        details = _parse_details(details_raw)

        message = (row.get('description') if isinstance(row, dict) else row['description']) or f'{detector} alert detected'
        logs.append({
            'id': str(row.get('id') if isinstance(row, dict) else row['id']),
            'timestamp': str(row.get('timestamp') if isinstance(row, dict) else row['timestamp']),
            'detector': detector,
            'alert_type': _extract_alert_type(detector, details),
            'severity': severity,
            'message': message,
            'source_ip': row.get('source_ip') if isinstance(row, dict) else row['source_ip'],
            'target_ip': row.get('target_ip') if isinstance(row, dict) else row['target_ip'],
        })

    return jsonify(logs)


# ---------------------------------------------------------------------------
# GET /api/rogue
# ---------------------------------------------------------------------------
@api_bp.route('/rogue', methods=['GET'])
def get_rogue_access():
    """Return nearby access points from the rogue_access detector (real only)."""
    manager = _get_manager()
    if manager is not None:
        return jsonify(manager.rogue_data())
    return jsonify({'authorized_aps': [], 'nearby_aps': []})


# ---------------------------------------------------------------------------
# GET /api/ssl
# ---------------------------------------------------------------------------
@api_bp.route('/ssl', methods=['GET'])
def get_ssl_strip():
    """Return SSL strip detections from the ssl_strip detector (real only)."""
    manager = _get_manager()
    if manager is not None:
        return jsonify(manager.ssl_data())
    return jsonify({'sessions': [], 'warnings': []})


# ---------------------------------------------------------------------------
# GET /api/detectors (health + statistics)
# ---------------------------------------------------------------------------
@api_bp.route('/detectors', methods=['GET'])
def get_detectors():
    """Return live detector health and statistics."""
    manager = _get_manager()
    if manager is None:
        return jsonify({'health': [], 'statistics': {}})
    return jsonify({
        'health': manager.detector_health(),
        'statistics': manager.detector_statistics(),
    })


# ---------------------------------------------------------------------------
# POST /api/start
# ---------------------------------------------------------------------------
@api_bp.route('/start', methods=['POST'])
def start_monitoring():
    """Start the real-time monitoring engine."""
    manager = _get_manager()
    if manager is None:
        return jsonify({'status': 'error', 'message': 'Monitoring engine unavailable'}), 500
    try:
        manager.start()
        return jsonify({'status': 'ok', 'message': 'Monitoring started', 'monitoring': manager.is_monitoring})
    except Exception as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 500


# ---------------------------------------------------------------------------
# POST /api/stop
# ---------------------------------------------------------------------------
@api_bp.route('/stop', methods=['POST'])
def stop_monitoring():
    """Stop the real-time monitoring engine."""
    manager = _get_manager()
    if manager is None:
        return jsonify({'status': 'error', 'message': 'Monitoring engine unavailable'}), 500
    try:
        manager.stop()
        return jsonify({'status': 'ok', 'message': 'Monitoring stopped', 'monitoring': manager.is_monitoring})
    except Exception as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 500


# ---------------------------------------------------------------------------
# POST /api/scan
# ---------------------------------------------------------------------------
@api_bp.route('/scan', methods=['POST'])
def trigger_scan():
    """Trigger a live network scan."""
    manager = _get_manager()
    if manager is None:
        return jsonify({'status': 'error', 'message': 'Monitoring engine unavailable'}), 500
    try:
        count = manager.network_monitor.scan()
        return jsonify({'status': 'ok', 'message': 'Network scan completed', 'devices_found': count})
    except Exception as exc:
        return jsonify({'status': 'error', 'message': str(exc)}), 500
