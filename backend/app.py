# backend/app.py
import atexit
import logging
import signal
import sys
from contextlib import asynccontextmanager
from typing import List, Dict, Any

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from utils.config import get_config
from utils.logger import setup_logging
from core.monitoring_manager import MonitoringManager

# ── Existing FastAPI routers (routers/ directory) ────────────────────────────
from routers.api import router as api_router
from routers.init_routes import router as init_router

# ── Converted FastAPI routers (routes/ directory — previously Flask Blueprints)
from routes.alerts import router as alerts_router
from routes.dashboard import router as dashboard_router
from routes.devices import router as devices_router
from routes.logs import router as logs_router
from routes.network import router as network_router
from routes.reports import router as reports_router

# Setup config and logging
config = get_config()
setup_logging()
# NOTE: Do NOT call logging.basicConfig() here — setup_logging() already
# configures the root logger. A second basicConfig() adds a duplicate
# StreamHandler to the root logger, causing every log message to print twice.
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Connection Manager for WebSockets
# ---------------------------------------------------------------------------
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected ({len(self.active_connections)} active)")

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info(f"WebSocket client disconnected ({len(self.active_connections)} active)")

    async def broadcast(self, message: Dict[str, Any]):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(message)
            except Exception:
                disconnected.append(connection)
        for conn in disconnected:
            self.disconnect(conn)


ws_manager = ConnectionManager()


def emit_event(event_name: str, data: dict) -> None:
    """General WebSocket event emitter wired to AlertManager and MonitoringManager."""
    try:
        import asyncio
        loop = asyncio.get_event_loop()
        if loop.is_running():
            loop.create_task(ws_manager.broadcast({"event": event_name, "data": data}))
    except Exception as exc:
        logger.debug(f"Emit event '{event_name}' warning: {exc}")

# Backward-compatibility alias
emit_alert = emit_event


# ---------------------------------------------------------------------------
# Global MonitoringManager singleton
# ---------------------------------------------------------------------------
monitoring_manager = MonitoringManager(emit_callback=emit_alert)


# ---------------------------------------------------------------------------
# Lifespan Handler for FastAPI
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    logger.info("Starting ShadowPulse FastAPI server...")
    if not monitoring_manager.is_monitoring:
        try:
            monitoring_manager.start()
            logger.info("ShadowPulse real-time monitoring engine started cleanly")
        except Exception as exc:
            logger.error(f"Error starting monitoring engine: {exc}")
    yield
    # Shutdown logic
    logger.info("Stopping ShadowPulse FastAPI server...")
    try:
        monitoring_manager.stop()
        logger.info("ShadowPulse real-time monitoring engine stopped cleanly")
    except Exception as exc:
        logger.error(f"Error stopping monitoring engine: {exc}")


# ---------------------------------------------------------------------------
# Create FastAPI App
# ---------------------------------------------------------------------------
app = FastAPI(
    title="ShadowPulse API",
    description="Real-Time Network Monitoring & MITM Attack Detection System",
    version="2.0.0",
    lifespan=lifespan,
)

# Store monitoring_manager on app.state for route dependency access
app.state.monitoring_manager = monitoring_manager

# ---------------------------------------------------------------------------
# CORS — FIXED: wildcard "allow_origins=["*"]" + allow_credentials=True is
# rejected by browsers. Use explicit origins instead.
# ---------------------------------------------------------------------------
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",   # Vite default dev port
        "http://localhost:5174",   # Vite alternate port
        "http://127.0.0.1:5173",
        "http://127.0.0.1:5174",
        "http://localhost:3000",   # CRA / other dev servers
        "http://localhost:4173",   # Vite preview
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Register routers — existing (routers/)
# ---------------------------------------------------------------------------
app.include_router(api_router)    # prefix: /api
app.include_router(init_router)   # prefix: /init

# ---------------------------------------------------------------------------
# Register routers — converted from Flask (routes/)
# FastAPI app
#     |
#     ├── /api/*         routers/api.py
#     ├── /init/*        routers/init_routes.py
#     ├── /dashboard/*   routes/dashboard.py
#     ├── /alerts/*      routes/alerts.py
#     ├── /devices/*     routes/devices.py
#     ├── /logs/*        routes/logs.py
#     ├── /network/*     routes/network.py
#     └── /reports/*     routes/reports.py
# ---------------------------------------------------------------------------
app.include_router(dashboard_router)  # prefix: /dashboard
app.include_router(alerts_router)     # prefix: /alerts
app.include_router(devices_router)    # prefix: /devices
app.include_router(logs_router)       # prefix: /logs
app.include_router(network_router)    # prefix: /network
app.include_router(reports_router)    # prefix: /reports


# Root Endpoint
@app.get("/")
def read_root():
    return {
        "system": "ShadowPulse",
        "status": "online",
        "monitoring": monitoring_manager.is_monitoring,
        "docs": "/docs"
    }


# WebSocket Endpoint for live alerts & events
@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await ws_manager.connect(websocket)
    try:
        # Send initial connection event
        await websocket.send_json({
            "event": "connected",
            "data": {
                "status": "ok",
                "monitoring": monitoring_manager.is_monitoring
            }
        })
        while True:
            # Keep connection alive and listen for ping/messages
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception as exc:
        logger.warning(f"WebSocket connection error: {exc}")
        ws_manager.disconnect(websocket)


# Graceful shutdown handler
def _signal_handler(signum, frame):
    logger.info(f"Received signal {signum}; shutting down...")
    try:
        monitoring_manager.stop()
    except Exception:
        pass
    sys.exit(0)

if hasattr(signal, 'SIGINT'):
    signal.signal(signal.SIGINT, _signal_handler)
if hasattr(signal, 'SIGTERM'):
    signal.signal(signal.SIGTERM, _signal_handler)


if __name__ == "__main__":
    port = int(config.get('API', 'port', 5000))
    host = config.get('API', 'host', "0.0.0.0")
    logger.info(f"Launching ShadowPulse FastAPI server on {host}:{port}")
    uvicorn.run("app:app", host=host, port=port, reload=False)
