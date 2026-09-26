"""
Network FastAPI router for ShadowPulse.
FastAPI APIRouter
All DB access uses centralized utils.database.
"""

import sqlite3
from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query

from utils.database import get_db_connection

# ── Router ──────────────────────────────────────────────────────────────────
router = APIRouter(prefix="/network", tags=["network"])


# ── GET /network/topology ─────────────────────────────────────────────────────
@router.get("/topology")
def get_network_topology():
    """Network topology: active devices (nodes) + connection data (edges)."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Active devices seen in last 1 h
        cursor.execute(
            """
            SELECT ip_address, mac_address, hostname, device_type, is_trusted
            FROM devices
            WHERE last_seen > datetime('now', '-1 hour')
            """
        )
        devices = cursor.fetchall()

        # Top 100 connections in last 1 h
        cursor.execute(
            """
            SELECT DISTINCT source_ip, destination_ip, protocol, COUNT(*) as connection_count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 hour')
            GROUP BY source_ip, destination_ip, protocol
            ORDER BY connection_count DESC
            LIMIT 100
            """
        )
        connections = cursor.fetchall()
        conn.close()

        nodes = [
            {
                "id": d["ip_address"],
                "label": d["hostname"] or d["ip_address"],
                "type": d["device_type"],
                "trusted": bool(d["is_trusted"]),
                "mac": d["mac_address"],
            }
            for d in devices
        ]

        edges = [
            {
                "source": c["source_ip"],
                "target": c["destination_ip"],
                "protocol": c["protocol"],
                "weight": c["connection_count"],
            }
            for c in connections
        ]

        return {
            "status": "success",
            "topology": {"nodes": nodes, "edges": edges},
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /network/traffic/realtime ──────────────────────────────────────────────
@router.get("/traffic/realtime")
def get_realtime_traffic():
    """Real-time traffic data: per-minute per-protocol counts + top talkers."""
    try:
        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Per-minute, per-protocol counts for last 5 min
        cursor.execute(
            """
            SELECT strftime('%Y-%m-%d %H:%M', timestamp) as minute,
                   protocol,
                   COUNT(*) as packet_count,
                   SUM(packet_size) as total_bytes
            FROM network_logs
            WHERE timestamp > datetime('now', '-5 minutes')
            GROUP BY strftime('%Y-%m-%d %H:%M', timestamp), protocol
            ORDER BY minute DESC
            """
        )
        traffic_data = [dict(r) for r in cursor.fetchall()]

        # Top talkers in last 1 min
        cursor.execute(
            """
            SELECT source_ip, destination_ip, COUNT(*) as packet_count
            FROM network_logs
            WHERE timestamp > datetime('now', '-1 minute')
            GROUP BY source_ip, destination_ip
            ORDER BY packet_count DESC
            LIMIT 10
            """
        )
        top_talkers = [dict(r) for r in cursor.fetchall()]
        conn.close()

        return {
            "status": "success",
            "traffic_data": traffic_data,
            "top_talkers": top_talkers,
            "timestamp": datetime.now().isoformat(),
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── GET /network/bandwidth ────────────────────────────────────────────────────
@router.get("/bandwidth")
def get_bandwidth_usage(
    period: Literal["hour", "day", "week"] = Query("hour", description="Time window")
):
    """Bandwidth usage statistics aggregated by time period and protocol."""
    try:
        if period == "hour":
            time_fmt = "%Y-%m-%d %H:%M"
            time_filter = "datetime('now', '-1 hour')"
        elif period == "day":
            time_fmt = "%Y-%m-%d %H"
            time_filter = "datetime('now', '-1 day')"
        else:  # week
            time_fmt = "%Y-%m-%d"
            time_filter = "datetime('now', '-7 days')"

        conn = get_db_connection()
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        cursor.execute(
            f"""
            SELECT strftime('{time_fmt}', timestamp) as time_period,
                   SUM(packet_size) as total_bytes,
                   COUNT(*) as packet_count
            FROM network_logs
            WHERE timestamp > {time_filter}
            GROUP BY strftime('{time_fmt}', timestamp)
            ORDER BY time_period
            """
        )
        bandwidth_data = [dict(r) for r in cursor.fetchall()]

        cursor.execute(
            f"""
            SELECT protocol, SUM(packet_size) as total_bytes
            FROM network_logs
            WHERE timestamp > {time_filter}
            GROUP BY protocol
            ORDER BY total_bytes DESC
            """
        )
        protocol_usage = [dict(r) for r in cursor.fetchall()]
        conn.close()

        return {
            "status": "success",
            "bandwidth_data": bandwidth_data,
            "protocol_usage": protocol_usage,
            "period": period,
        }

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
