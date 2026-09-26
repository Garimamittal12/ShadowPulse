"""
Logs FastAPI router for ShadowPulse.
FastAPI APIRouter
All DB access uses centralized utils.database.
"""

import json
import os
import sqlite3
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from utils.database import get_db_connection

# ── Router ──────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/logs", tags=["logs"])

_LOG_COLUMNS = [
    "id", "timestamp", "source_ip", "destination_ip",
    "source_port", "destination_port", "protocol",
    "packet_size", "flags", "payload_hash", "payload_snippet",
    "session_id", "created_at",
]


def _row_to_dict(row: sqlite3.Row) -> dict:
    return dict(row)


# ── GET /logs ─────────────────────────────────────────────────────────────────
@router.get("/")
def get_logs(
    log_type: Optional[str] = Query(None, alias="type", description="Filter by log_type"),
    start_time: Optional[str] = Query(None),
    end_time: Optional[str] = Query(None),
    source_ip: Optional[str] = Query(None),
    limit: int = Query(1000, ge=1, le=5000),
):
    """Get network logs with optional filtering."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        query = "SELECT * FROM network_logs WHERE 1=1"
        params: list = []

        # NOTE: network_logs has no log_type column in the actual schema;
        # filtering by it is a no-op but kept for API compatibility.
        if log_type and log_type != "all":
            query += " AND log_type = ?"
            params.append(log_type)
        if start_time:
            query += " AND timestamp >= ?"
            params.append(start_time)
        if end_time:
            query += " AND timestamp <= ?"
            params.append(end_time)
        if source_ip:
            query += " AND source_ip = ?"
            params.append(source_ip)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        return {
            "status": "success",
            "logs": [_row_to_dict(r) for r in rows],
            "count": len(rows),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── POST /logs/export ─────────────────────────────────────────────────────────
class ExportFilters(BaseModel):
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    source_ip: Optional[str] = None
    limit: int = 1000


class ExportPayload(BaseModel):
    format: str = "json"
    filters: ExportFilters = ExportFilters()


@router.post("/export")
def export_logs(payload: ExportPayload):
    """Export filtered network logs to a JSON file in the exports/ directory."""
    try:
        f = payload.filters
        query = "SELECT * FROM network_logs WHERE 1=1"
        params: list = []

        if f.start_time:
            query += " AND timestamp >= ?"
            params.append(f.start_time)
        if f.end_time:
            query += " AND timestamp <= ?"
            params.append(f.end_time)
        if f.source_ip:
            query += " AND source_ip = ?"
            params.append(f.source_ip)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(f.limit)

        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        conn.close()

        log_list = [dict(r) for r in rows]

        # Write export file
        os.makedirs("exports", exist_ok=True)
        export_id = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        file_name = f"exports/{export_id}.json"
        with open(file_name, "w", encoding="utf-8") as fh:
            json.dump(
                {"export_id": export_id, "exported_at": datetime.now().isoformat(), "rows": log_list},
                fh,
                default=str,
            )

        return {
            "status": "success",
            "message": "Log export completed",
            "export_id": export_id,
            "file": file_name,
            "format": payload.format,
            "count": len(log_list),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── POST /logs/search ─────────────────────────────────────────────────────────
class SearchPayload(BaseModel):
    search_term: str = ""
    limit: int = 500


@router.post("/search")
def search_logs(payload: SearchPayload):
    """Full-text search across source_ip, destination_ip, and payload_snippet."""
    try:
        term = f"%{payload.search_term}%"
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT * FROM network_logs
            WHERE source_ip LIKE ? OR destination_ip LIKE ? OR payload_snippet LIKE ?
            ORDER BY timestamp DESC
            LIMIT ?
            """,
            (term, term, term, payload.limit),
        )
        rows = cursor.fetchall()
        conn.close()

        return {
            "status": "success",
            "results": [dict(r) for r in rows],
            "count": len(rows),
            "search_term": payload.search_term,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
