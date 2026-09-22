"""
Initialization and System Health FastAPI router for ShadowPulse.
"""

import os
import shutil
from datetime import datetime
from typing import Any, Dict
from fastapi import APIRouter, HTTPException, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel

from utils.database import get_db_manager

router = APIRouter(prefix="/init", tags=["init"])


def create_database_tables():
    """Delegate table creation to the central DatabaseManager."""
    get_db_manager()


def insert_default_data():
    """Insert default configuration and initial detector status via DB manager."""
    db = get_db_manager()
    default_configs = [
        ('monitoring_interface', 'auto', 'Network interface to monitor'),
        ('alert_retention_days', '30', 'Days to retain alert data'),
        ('log_retention_days', '7', 'Days to retain network logs'),
        ('scan_interval', '300', 'Device scan interval in seconds'),
        ('threat_threshold', '5', 'Threat score threshold for alerts'),
        ('admin_email', 'admin@shadowpulse.local', 'Administrator email for alerts')
    ]
    detectors = [
        'arp_spoof', 'dhcp_spoofing', 'dns_spoof', 'http_injection',
        'icmp_redirect', 'rogue_access', 'ssl_strip'
    ]
    with db.get_connection() as conn:
        cursor = conn.cursor()
        for key, value, desc in default_configs:
            cursor.execute('''
                INSERT OR IGNORE INTO system_config (config_key, config_value, description)
                VALUES (?, ?, ?)
            ''', (key, value, desc))
        for detector in detectors:
            cursor.execute('''
                INSERT OR IGNORE INTO detector_status (detector_name, is_enabled, status)
                VALUES (?, 1, 'running')
            ''', (detector,))
        conn.commit()


@router.post("/setup")
def initialize_system():
    """Initialize the SHADOWPULSE system"""
    try:
        create_database_tables()
        insert_default_data()
        
        directories = ['logs', 'exports', 'reports', 'captures']
        for directory in directories:
            os.makedirs(directory, exist_ok=True)
        
        return {
            'status': 'success',
            'message': 'SHADOWPULSE system initialized successfully',
            'initialized_at': datetime.now().isoformat()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/status")
def get_system_status():
    """Get current system initialization status"""
    try:
        db = get_db_manager()
        try:
            with db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('alerts','network_logs','devices')")
                tables = cursor.fetchall()
                cursor.execute('SELECT detector_name, is_enabled, status FROM detector_status')
                detectors = cursor.fetchall()
                is_initialized = len(tables) >= 3
        except Exception:
            is_initialized = False
            detectors = []

        return {
            'status': 'success',
            'is_initialized': is_initialized,
            'detectors': [
                {
                    'name': d[0],
                    'enabled': bool(d[1]),
                    'status': d[2]
                } for d in detectors
            ] if detectors else []
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/config")
def get_system_config():
    """Get system configuration"""
    try:
        db = get_db_manager()
        config_dict = {}
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT config_key, config_value, description FROM system_config')
            configs = cursor.fetchall()
            for config in configs:
                config_dict[config[0]] = {
                    'value': config[1],
                    'description': config[2]
                }
        
        return {
            'status': 'success',
            'configuration': config_dict
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.put("/config")
def update_system_config(data: Dict[str, Any]):
    """Update system configuration"""
    try:
        db = get_db_manager()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            for key, value in data.items():
                cursor.execute('''
                    UPDATE system_config 
                    SET config_value = ?, updated_at = datetime('now')
                    WHERE config_key = ?
                ''', (str(value), key))
            conn.commit()
        
        return {
            'status': 'success',
            'message': 'Configuration updated successfully'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


class DetectorConfigPayload(BaseModel):
    detector_name: str
    is_enabled: bool
    config: Dict[str, Any] = {}


@router.put("/detectors")
def update_detector_config(payload: DetectorConfigPayload):
    """Update detector configuration and status"""
    try:
        db = get_db_manager()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute('''
                UPDATE detector_status 
                SET is_enabled = ?, config = ?, last_update = datetime('now')
                WHERE detector_name = ?
            ''', (int(payload.is_enabled), str(payload.config), payload.detector_name))
            conn.commit()
        
        return {
            'status': 'success',
            'message': f'Detector {payload.detector_name} configuration updated'
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/health")
def health_check():
    """System health check endpoint (Cross-platform, Windows-compatible)."""
    try:
        # Check database connectivity — use centralized DB manager (no hardcoded path)
        db_healthy = False
        try:
            db = get_db_manager()
            with db.get_connection() as conn:
                conn.execute('SELECT 1')
            db_healthy = True
        except Exception:
            db_healthy = False

        # Check disk space using shutil (works on Windows, Linux, macOS)
        total_b, used_b, free_b = shutil.disk_usage('.')
        disk_usage_percent = (used_b / total_b) * 100 if total_b > 0 else 0.0

        # Check if critical directories exist
        required_dirs = ['logs', 'exports', 'reports', 'captures']
        dirs_exist = all(os.path.exists(d) for d in required_dirs)

        health_status = {
            'database': 'healthy' if db_healthy else 'unhealthy',
            'disk_usage_percent': round(disk_usage_percent, 2),
            'free_space_gb': round(free_b / (1024**3), 2),
            'directories': 'ok' if dirs_exist else 'missing',
            'timestamp': datetime.now().isoformat()
        }

        overall_status = 'healthy' if (db_healthy and disk_usage_percent < 95 and dirs_exist) else 'unhealthy'

        return {
            'status': 'success',
            'overall_health': overall_status,
            'details': health_status
        }
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={
                'status': 'error',
                'overall_health': 'unhealthy',
                'message': str(e)
            }
        )
