"""
Alerts FastAPI router for ShadowPulse.
FastAPI APIRouter
All routes use centralized DB via utils.database.
"""

import json
import sqlite3
from datetime import datetime, timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from utils.database import get_db_connection, get_db_manager

# ── Router ──────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/alerts", tags=["alerts"])


# ── Helper ───────────────────────────────────────────────────────────────────
def _row_to_dict(row) -> dict:
    """Convert a sqlite3.Row or tuple from the alerts table to a clean dict."""
    if isinstance(row, sqlite3.Row):
        d = dict(row)
        # Parse stored JSON details field
        if isinstance(d.get("details"), str):
            try:
                d["details"] = json.loads(d["details"])
            except (json.JSONDecodeError, TypeError):
                d["details"] = {}
        return d
    # Legacy tuple fallback (col order: id,timestamp,detector_type,severity,
    #   source_ip,target_ip,source_mac,target_mac,protocol,description,details,
    #   status,notes,resolved_by,resolved_at,created_at,updated_at)
    return {
        "id": row[0],
        "timestamp": row[1],
        "detector_type": row[2],
        "severity": row[3],
        "source_ip": row[4],
        "target_ip": row[5],
        "source_mac": row[6],
        "target_mac": row[7],
        "protocol": row[8],
        "description": row[9],
        "details": json.loads(row[10]) if row[10] else {},
        "status": row[11] if len(row) > 11 else "new",
    }


# ── GET /alerts ───────────────────────────────────────────────────────────────
@router.get("/")
def get_alerts(
    severity: Optional[str] = Query(None, description="Filter by severity (low/medium/high/critical)"),
    limit: int = Query(100, ge=1, le=1000),
):
    """Get all security alerts with optional severity filtering."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if severity and severity != "all":
            cursor.execute(
                "SELECT * FROM alerts WHERE severity = ? ORDER BY timestamp DESC LIMIT ?",
                (severity, limit),
            )
        else:
            cursor.execute(
                "SELECT * FROM alerts ORDER BY timestamp DESC LIMIT ?",
                (limit,),
            )

        rows = cursor.fetchall()
        conn.close()

        alert_list = [_row_to_dict(r) for r in rows]
        return {"status": "success", "alerts": alert_list, "count": len(alert_list)}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /alerts/stats ─────────────────────────────────────────────────────────
@router.get("/stats")
def get_alert_stats():
    """Get alert statistics for the dashboard (last 24 h / 7 days)."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Counts by severity in last 24 h
        cursor.execute(
            """
            SELECT severity, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY severity
            """
        )
        severity_stats = {row["severity"]: row["count"] for row in cursor.fetchall()}

        # Daily trend for last 7 days
        cursor.execute(
            """
            SELECT DATE(timestamp) as date, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-7 days')
            GROUP BY DATE(timestamp)
            ORDER BY date
            """
        )
        trend_data = [{"date": r["date"], "count": r["count"]} for r in cursor.fetchall()]

        # Top attack types (detector_type) in last 24 h
        cursor.execute(
            """
            SELECT detector_type, COUNT(*) as count
            FROM alerts
            WHERE timestamp > datetime('now', '-24 hours')
            GROUP BY detector_type
            ORDER BY count DESC
            LIMIT 5
            """
        )
        top_attacks = [{"type": r["detector_type"], "count": r["count"]} for r in cursor.fetchall()]

        conn.close()

        return {
            "status": "success",
            "severity_stats": severity_stats,
            "trend_data": trend_data,
            "top_attacks": top_attacks,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── PUT /alerts/{alert_id} ────────────────────────────────────────────────────
class AlertUpdatePayload(BaseModel):
    status: Optional[str] = None  # new | investigating | resolved | false_positive
    notes: Optional[str] = None


@router.put("/{alert_id}")
def update_alert(alert_id: int, payload: AlertUpdatePayload):
    """Update alert status or add analyst notes."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()

        if payload.status is not None:
            cursor.execute(
                "UPDATE alerts SET status = ?, updated_at = datetime('now') WHERE id = ?",
                (payload.status, alert_id),
            )
        if payload.notes is not None:
            cursor.execute(
                "UPDATE alerts SET notes = ?, updated_at = datetime('now') WHERE id = ?",
                (payload.notes, alert_id),
            )

        conn.commit()
        conn.close()

        return {"status": "success", "message": "Alert updated"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
