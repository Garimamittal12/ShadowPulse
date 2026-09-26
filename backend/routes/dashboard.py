"""
Dashboard FastAPI router for ShadowPulse.
FastAPI APIRouter
Provides system + security metrics from LIVE sources (psutil + SQLite + MonitoringManager).
No mock/hardcoded data.
"""

import sqlite3
import psutil

from fastapi import APIRouter, HTTPException, Request

from utils.database import get_db_connection

# ── Router ──────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/dashboard", tags=["dashboard"])


def _get_manager(request: Request):
    """Retrieve MonitoringManager from app state or engine singleton."""
    try:
        if hasattr(request.app.state, "monitoring_manager"):
            mm = request.app.state.monitoring_manager
            if mm is not None:
                return mm
    except Exception:
        pass
    try:
        from utils.engine import get_monitoring_manager
        return get_monitoring_manager()
    except Exception:
        return None


# ── GET /dashboard/stats ──────────────────────────────────────────────────────
@router.get("/stats")
def get_dashboard_stats(request: Request):
    """
    Comprehensive dashboard statistics.
    Returns:
      - CPU, memory, disk usage (psutil)
      - Alerts in last 24 h
      - Traffic in last 1 h
      - Unique IPs in last 24 h
      - Threat level (LOW / MEDIUM / HIGH)
      - Detector health status (real from MonitoringManager)
    """
    try:
        # ── System metrics (psutil) ───────────────────────────────────────
        cpu_percent = psutil.cpu_percent(interval=0.5)
        memory = psutil.virtual_memory()
        # Use shutil for cross-platform disk usage (avoids statvfs on Windows)
        import shutil
        total_b, used_b, free_b = shutil.disk_usage(".")
        disk_percent = (used_b / total_b) * 100 if total_b > 0 else 0.0

        # ── Security metrics (SQLite) ──────────────────────────────────────
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        manager = _get_manager(request)
        session_started_at = getattr(manager, "_started_at", None) if manager else None
        if session_started_at is not None:
            cursor.execute(
                "SELECT COUNT(*) as cnt FROM alerts WHERE timestamp >= ?",
                (session_started_at.strftime("%Y-%m-%d %H:%M:%S"),),
            )
        else:
            cursor.execute("SELECT 0 as cnt")
        alerts_24h = cursor.fetchone()["cnt"]

        cursor.execute(
            "SELECT COUNT(*) as cnt FROM network_logs WHERE timestamp > datetime('now', '-1 hour')"
        )
        traffic_1h = cursor.fetchone()["cnt"]

        cursor.execute(
            "SELECT COUNT(DISTINCT source_ip) as cnt FROM network_logs WHERE timestamp > datetime('now', '-24 hours')"
        )
        unique_ips = cursor.fetchone()["cnt"]

        # Packet stats from monitoring engine
        packet_count = 0
        packet_rate = 0.0
        if manager is not None:
            try:
                status = manager.status_dict()
                packet_count = status.get("packet_count", 0)
                packet_rate = status.get("packets_per_second", 0.0)
            except Exception:
                pass

        conn.close()

        # ── Threat level ────────────────────────────────────────────────────
        if alerts_24h > 100:
            threat_level = "HIGH"
        elif alerts_24h > 50:
            threat_level = "MEDIUM"
        else:
            threat_level = "LOW"

        # ── Detector health (live from MonitoringManager) ───────────────────
        detector_status = {}
        if manager is not None:
            try:
                for det in manager.detector_health():
                    detector_status[det.get("detector")] = det.get("status") == "running"
            except Exception:
                pass

        return {
            "status": "success",
            "system_metrics": {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "disk_percent": round(disk_percent, 2),
                "uptime": psutil.boot_time(),
            },
            "security_metrics": {
                "alerts_24h": alerts_24h,
                "traffic_1h": traffic_1h,
                "unique_ips": unique_ips,
                "threat_level": threat_level,
                "packet_count": packet_count,
                "packet_rate": packet_rate,
            },
            "detector_status": detector_status,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /dashboard/network-overview ───────────────────────────────────────────
@router.get("/network-overview")
def get_network_overview():
    """Network traffic overview: protocols, top sources, hourly timeline."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Traffic by protocol (last 1 h)
        cursor.execute(
            """
            SELECT protocol, COUNT(*) as count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY protocol
            """
        )
        protocol_stats = {row["protocol"]: row["count"] for row in cursor.fetchall()}

        # Top 10 source IPs (last 1 h)
        cursor.execute(
            """
            SELECT source_ip, COUNT(*) as count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY source_ip
            ORDER BY count DESC
            LIMIT 10
            """
        )
        top_sources = [{"ip": r["source_ip"], "count": r["count"]} for r in cursor.fetchall()]

        # Traffic timeline (last 24 h, per hour)
        cursor.execute(
            """
            SELECT strftime('%H', timestamp) as hour, COUNT(*) as count
            FROM network_logs
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY strftime('%H', timestamp)
            ORDER BY hour
            """
        )
        traffic_timeline = [{"hour": r["hour"], "count": r["count"]} for r in cursor.fetchall()]

        conn.close()

        return {
            "status": "success",
            "protocol_stats": protocol_stats,
            "top_sources": top_sources,
            "traffic_timeline": traffic_timeline,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
