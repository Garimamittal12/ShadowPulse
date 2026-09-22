"""
Consolidated FastAPI API router for ShadowPulse.

All `/api/*` endpoints return data from LIVE sources only:
    - MonitoringManager (runtime state, packet counters, detector health)
    - NetworkMonitor (discovered devices)
    - AlertManager / SQLite (alerts, logs, statistics)
    - Detector instances (rogue AP, SSL strip)

There are NO random values, NO hardcoded devices, and NO fabricated metrics.
"""

import json
import sqlite3
from typing import Optional
from fastapi import APIRouter, Request, HTTPException, Query, Response, status
from fastapi.responses import JSONResponse

from utils.database import get_db_manager, get_db_connection

router = APIRouter(prefix="/api", tags=["api"])

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


def _get_manager(request: Optional[Request] = None):
    """Return the global MonitoringManager from app state or singleton."""
    if request is not None and hasattr(request.app.state, "monitoring_manager"):
        mm = request.app.state.monitoring_manager
        if mm is not None:
            return mm
    try:
        from utils.engine import get_monitoring_manager
        return get_monitoring_manager()
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
@router.get("/status")
def get_status(request: Request):
    """Return live monitoring status from the real engine."""
    manager = _get_manager(request)
    if manager is not None:
        return manager.status_dict()

    return {
        'monitoring': False,
        'interface': None,
        'started_at': None,
        'uptime_seconds': 0,
        'packet_count': 0,
        'packets_per_second': 0.0,
        'detectors_enabled': {},
        'detector_status': {},
        'thread_status': {},
    }


# ---------------------------------------------------------------------------
# GET /api/alerts
# ---------------------------------------------------------------------------
@router.get("/alerts")
def get_alerts(request: Request, limit: int = Query(100, ge=1, le=1000)):
    """Return alerts from the active monitoring run, newest first."""
    alerts = []
    manager = _get_manager(request)
    session_started_at = getattr(manager, "_started_at", None) if manager else None
    if session_started_at is None:
        return alerts
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, timestamp, detector_type, severity, source_ip, target_ip, "
            "source_mac, target_mac, protocol, description, details "
            "FROM alerts WHERE timestamp >= ? ORDER BY timestamp DESC LIMIT ?",
            (session_started_at.strftime("%Y-%m-%d %H:%M:%S"), limit),
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

    return alerts


# ---------------------------------------------------------------------------
# GET /api/network
# ---------------------------------------------------------------------------
@router.get("/network")
def get_network(request: Request):
    """Return discovered devices from NetworkMonitor (no fabricated devices)."""
    manager = _get_manager(request)
    if manager is not None:
        return manager.network_data()

    return {
        'gateway': None,
        'interface': None,
        'packet_count': 0,
        'packet_rate': 0.0,
        'devices': [],
    }


# ---------------------------------------------------------------------------
# GET /api/statistics
# ---------------------------------------------------------------------------
@router.get("/statistics")
def get_statistics(request: Request):
    """Return statistics computed from SQLite + runtime metrics (no random)."""
    manager = _get_manager(request)
    if manager is not None:
        return manager.statistics_data()

    return {
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
    }


# ---------------------------------------------------------------------------
# GET /api/logs
# ---------------------------------------------------------------------------
@router.get("/logs")
def get_logs(limit: int = Query(200, ge=1, le=2000)):
    """Return real log entries from SQLite."""
    logs = []
    try:
        db = get_db_manager()
        rows = db.get_alerts(limit=limit)
    except Exception:
        rows = []

    for row in rows:
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

    return logs


# ---------------------------------------------------------------------------
# GET /api/rogue
# ---------------------------------------------------------------------------
@router.get("/rogue")
def get_rogue_access(request: Request):
    """Return nearby access points from the rogue_access detector (real only)."""
    manager = _get_manager(request)
    if manager is not None:
        return manager.rogue_data()
    return {'authorized_aps': [], 'nearby_aps': []}


# ---------------------------------------------------------------------------
# GET /api/ssl
# ---------------------------------------------------------------------------
@router.get("/ssl")
def get_ssl_strip(request: Request):
    """Return SSL strip detections from the ssl_strip detector (real only)."""
    manager = _get_manager(request)
    if manager is not None:
        return manager.ssl_data()
    return {'sessions': [], 'warnings': []}


# ---------------------------------------------------------------------------
# GET /api/detectors (health + statistics)
# ---------------------------------------------------------------------------
@router.get("/detectors")
def get_detectors(request: Request):
    """Return live detector health and statistics."""
    manager = _get_manager(request)
    if manager is None:
        return {'health': [], 'statistics': {}}
    return {
        'health': manager.detector_health(),
        'statistics': manager.detector_statistics(),
    }


# ---------------------------------------------------------------------------
# POST /api/start
# ---------------------------------------------------------------------------
@router.post("/start")
def start_monitoring(request: Request):
    """Start the real-time monitoring engine."""
    manager = _get_manager(request)
    if manager is None:
        raise HTTPException(status_code=500, detail="Monitoring engine unavailable")
    try:
        manager.start()
        return {'status': 'ok', 'message': 'Monitoring started', 'monitoring': manager.is_monitoring}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /api/stop
# ---------------------------------------------------------------------------
@router.post("/stop")
def stop_monitoring(request: Request):
    """Stop the real-time monitoring engine."""
    manager = _get_manager(request)
    if manager is None:
        raise HTTPException(status_code=500, detail="Monitoring engine unavailable")
    try:
        manager.stop()
        return {'status': 'ok', 'message': 'Monitoring stopped', 'monitoring': manager.is_monitoring}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


# ---------------------------------------------------------------------------
# POST /api/scan
# ---------------------------------------------------------------------------
@router.post("/scan")
def trigger_scan(request: Request):
    """Trigger a live network scan."""
    manager = _get_manager(request)
    if manager is None:
        raise HTTPException(status_code=500, detail="Monitoring engine unavailable")
    try:
        count = manager.network_monitor.scan()
        return {'status': 'ok', 'message': 'Network scan completed', 'devices_found': count}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))
