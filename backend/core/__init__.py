"""
ShadowPulse Core Engine
=======================
Core real-time monitoring architecture:

    Network Interface
          │
          ▼
    AsyncSniffer (single scapy sniffer)
          │
          ▼
    PacketDispatcher
          │
          ▼
    Registered Detectors
          │
          ▼
    AlertManager
          │
          ▼
    SQLite → FastAPI REST snapshots + WebSocket events → React Dashboard

Exposed components:
- PacketDispatcher   : single sniffer + packet fan-out
- AlertManager       : dedupe, severity, SQLite, WebSocket emit
- MonitoringManager  : owns dispatcher, detectors, state, runtime stats
- Scheduler          : APScheduler-based periodic jobs
- Statistics         : DB-driven statistics engine (no randomness)
- NetworkMonitor     : live device discovery (ARP scan + passive learning)
"""

from .packet_dispatcher import PacketDispatcher
from .alert_manager import AlertManager
from .monitoring_manager import MonitoringManager
from .scheduler import Scheduler
from .statistics import StatisticsEngine
from .network_monitor import NetworkMonitor

__all__ = [
    "PacketDispatcher",
    "AlertManager",
    "MonitoringManager",
    "Scheduler",
    "StatisticsEngine",
    "NetworkMonitor",
]

