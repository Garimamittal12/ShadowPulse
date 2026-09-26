"""
Devices FastAPI router for ShadowPulse.
FastAPI APIRouter
All DB access uses centralized utils.database.
"""

import json
import sqlite3
from typing import Optional

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from utils.database import get_db_connection

# ── Router ──────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/devices", tags=["devices"])


def _device_row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a devices table Row to a clean dict."""
    d = dict(row)
    # Parse JSON-encoded list columns
    for col in ("open_ports", "services"):
        if isinstance(d.get(col), str):
            try:
                d[col] = json.loads(d[col])
            except (json.JSONDecodeError, TypeError):
                d[col] = []
    return d


# ── GET /devices ──────────────────────────────────────────────────────────────
@router.get("/")
def get_devices(include_inactive: bool = Query(False, description="Include devices not seen in last 24 h")):
    """Get all discovered network devices, newest-seen first."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if include_inactive:
            cursor.execute("""
                SELECT * FROM devices
                WHERE lower(COALESCE(mac_address, '')) NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                ORDER BY last_seen DESC
            """)
        else:
            cursor.execute(
                """
                SELECT * FROM devices
                WHERE last_seen > datetime('now', '-24 hours')
                  AND lower(COALESCE(mac_address, '')) NOT IN ('ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00')
                ORDER BY last_seen DESC
                """
            )

        rows = cursor.fetchall()
        conn.close()

        return {
            "status": "success",
            "devices": [_device_row_to_dict(r) for r in rows],
            "count": len(rows),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── POST /devices/scan ────────────────────────────────────────────────────────
class ScanPayload(BaseModel):
    network_range: Optional[str] = None


@router.post("/scan")
def initiate_device_scan(request: Request, payload: ScanPayload = ScanPayload()):
    """Trigger a real network device discovery scan via MonitoringManager."""
    try:
        mm = None
        if hasattr(request.app.state, "monitoring_manager"):
            mm = request.app.state.monitoring_manager
        if mm is None:
            from utils.engine import get_monitoring_manager
            mm = get_monitoring_manager()
        if mm is None:
            raise HTTPException(status_code=503, detail="Monitoring engine unavailable")

        count = mm.network_monitor.scan(network_range=payload.network_range)
        return {
            "status": "success",
            "message": "Device scan completed",
            "devices_found": count,
            "network_range": payload.network_range,
        }

    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan failed: {e}")


# ── PUT /devices/{device_id}/trust ────────────────────────────────────────────
class TrustPayload(BaseModel):
    is_trusted: bool = False


@router.put("/{device_id}/trust")
def update_device_trust(device_id: int, payload: TrustPayload):
    """Mark a device as trusted or untrusted."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE devices SET is_trusted = ?, updated_at = datetime('now') WHERE id = ?",
            (int(payload.is_trusted), device_id),
        )
        conn.commit()
        conn.close()
        return {"status": "success", "message": "Device trust status updated"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /devices/rogue ────────────────────────────────────────────────────────
@router.get("/rogue")
def get_rogue_devices():
    """Get devices identified as potentially rogue (untrusted + risk_score > 5)."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM devices WHERE is_trusted = 0 AND risk_score > 5 ORDER BY risk_score DESC"
        )
        rows = cursor.fetchall()
        conn.close()

        return {
            "status": "success",
            "rogue_devices": [_device_row_to_dict(r) for r in rows],
            "count": len(rows),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
