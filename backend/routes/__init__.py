"""FastAPI feature-router exports."""

from routes.alerts import router as alerts_router
from routes.dashboard import router as dashboard_router
from routes.devices import router as devices_router
from routes.logs import router as logs_router
from routes.network import router as network_router
from routes.reports import router as reports_router

__all__ = [
    "alerts_router",
    "dashboard_router",
    "devices_router",
    "logs_router",
    "network_router",
    "reports_router",
]
