"""
AlertManager
============
Central hub for the security-alert pipeline.

Detectors never touch the database or the API directly. They call
``AlertManager.raise_alert(...)`` and the manager is responsible for:

    - de-duplicating alerts (fingerprint + cooldown window)
    - computing / normalizing severity
    - enriching with runtime metadata
    - inserting into SQLite (thread-safe)
    - maintaining an in-memory alert cache for fast API reads
    - emitting WebSocket events to the frontend (when SocketIO is attached)

The manager is fully thread-safe: detectors run in daemon threads and call
``raise_alert`` concurrently.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional

from utils.logger import get_logger
from utils.database import get_db_manager

logger = get_logger()

# Severity ordering for escalation decisions.
SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]
SEVERITY_RANK = {s: i for i, s in enumerate(SEVERITY_ORDER)}

# Fields that identify "the same" attack for de-duplication purposes.
_FINGERPRINT_FIELDS = ("detector", "alert_type", "source_ip", "target_ip")


class AlertManager:
    """Thread-safe alert deduplication, persistence, and notification."""

    def __init__(
        self,
        cooldown_seconds: int = 30,
        max_cache_size: int = 200,
        emit_callback: Optional[Callable[[str, Any], None]] = None,
    ):
        self.cooldown_seconds = cooldown_seconds
        self.max_cache_size = max_cache_size

        # Callback used to push realtime notifications (e.g., socketio.emit).
        # Signature: emit_callback(event_name: str, data: dict) -> None
        self._emit_callback = emit_callback

        self._db = get_db_manager()

        self._lock = threading.RLock()
        # fingerprint -> last emitted timestamp
        self._last_seen: Dict[str, datetime] = {}
        # in-memory cache of recent alerts (newest first)
        self._cache: List[dict] = []
        # client IP -> detector evidence observed in the correlation window.
        self._correlation_evidence: Dict[str, Dict[str, datetime]] = {}
        self._correlation_cooldown: Dict[str, datetime] = {}

    # ------------------------------------------------------------------
    # Public API used by detectors
    # ------------------------------------------------------------------
    def raise_alert(
        self,
        detector: str,
        alert_type: str,
        details: Optional[dict] = None,
        severity: Optional[str] = None,
        source_ip: Optional[str] = None,
        target_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        target_mac: Optional[str] = None,
        protocol: Optional[str] = None,
        description: Optional[str] = None,
    ) -> Optional[dict]:
        """Submit an alert for processing.

        Returns the serialized alert dict if it was accepted (i.e., not a
        duplicate), or ``None`` if it was suppressed by the de-duplication
        window.
        """
        details = details or {}
        severity = self._normalize_severity(severity, details)
        description = description or details.get("description") or (
            f"{alert_type} detected by {detector}"
        )

        # Build a stable fingerprint for de-duplication.
        fingerprint = self._fingerprint(
            detector, alert_type, source_ip, target_ip, source_mac, target_mac
        )

        with self._lock:
            now = datetime.utcnow()
            last = self._last_seen.get(fingerprint)
            if last is not None and (now - last).total_seconds() < self.cooldown_seconds:
                return None

            self._last_seen[fingerprint] = now
            # Bound memory growth of the dedupe map.
            if len(self._last_seen) > 5000:
                cutoff = now - timedelta(hours=1)
                self._last_seen = {
                    k: v for k, v in self._last_seen.items() if v > cutoff
                }

        alert_dict = {
            "timestamp": now.isoformat() + "Z",
            "detector": detector,
            "alert_type": alert_type,
            "severity": severity,
            "source_ip": source_ip,
            "target_ip": target_ip,
            "source_mac": source_mac,
            "target_mac": target_mac,
            "protocol": protocol,
            "description": description,
            "details": details,
        }

        # Persist to SQLite.
        alert_id = self._persist(alert_dict)
        alert_dict["id"] = str(alert_id)

        # Update the in-memory cache.
        self._cache_append(alert_dict)

        # Promote only corroborated, independent indicators.  This is kept in
        # the alert layer so detector modules remain focused on packet facts.
        self._correlate_mitm_indicators(alert_dict)

        # Emit WebSocket event (best-effort; must never break detection).
        self._notify(alert_dict)

        logger.warning(
            f"ALERT [{severity.upper()}] {detector}:{alert_type} "
            f"src={source_ip} dst={target_ip} — {description}"
        )
        return alert_dict

    def _correlate_mitm_indicators(self, alert: dict) -> None:
        """Create one high-confidence alert for DNS + HTTPS downgrade evidence.

        Correlation is deliberately conservative: both evidence families must
        refer to the same client within five minutes.  It never upgrades a
        single heuristic into an attack on its own.
        """
        detector = alert.get("detector")
        if detector not in {"dns_spoof", "ssl_strip"}:
            return
        details = alert.get("details") or {}
        client_ip = details.get("client_ip") or alert.get("target_ip")
        if not client_ip:
            return

        now = datetime.utcnow()
        with self._lock:
            evidence = self._correlation_evidence.setdefault(client_ip, {})
            evidence[detector] = now
            cutoff = now - timedelta(minutes=5)
            self._correlation_evidence[client_ip] = {
                kind: ts for kind, ts in evidence.items() if ts >= cutoff
            }
            evidence = self._correlation_evidence[client_ip]
            if not {"dns_spoof", "ssl_strip"}.issubset(evidence):
                return
            last = self._correlation_cooldown.get(client_ip)
            if last and now - last < timedelta(minutes=10):
                return
            self._correlation_cooldown[client_ip] = now

        self.raise_alert(
            detector="threat_correlation",
            alert_type="possible_mitm_chain",
            severity="critical",
            source_ip=client_ip,
            target_ip=None,
            details={
                "client_ip": client_ip,
                "evidence": ["dns_spoof", "ssl_strip"],
                "severity": "critical",
                "description": (
                    "DNS manipulation evidence and an HTTPS downgrade indicator "
                    "were observed for the same client within five minutes"
                ),
            },
        )

    # ------------------------------------------------------------------
    # Alert cache (fast reads for REST API)
    # ------------------------------------------------------------------
    def recent_alerts(self, limit: int = 100) -> List[dict]:
        """Return most recent accepted alerts from the in-memory cache."""
        with self._lock:
            return list(self._cache[:limit])

    def _cache_append(self, alert: dict) -> None:
        with self._lock:
            self._cache.insert(0, alert)
            if len(self._cache) > self.max_cache_size:
                self._cache = self._cache[: self.max_cache_size]

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _persist(self, alert: dict) -> int:
        try:
            return self._db.insert_alert(
                detector_type=alert["detector"],
                severity=alert["severity"],
                description=alert["description"],
                source_ip=alert["source_ip"],
                target_ip=alert["target_ip"],
                source_mac=alert["source_mac"],
                target_mac=alert["target_mac"],
                protocol=alert["protocol"],
                details=alert["details"],
            )
        except Exception as exc:
            logger.error(f"AlertManager: failed to persist alert: {exc}")
            return 0

    # ------------------------------------------------------------------
    # Notification (WebSocket / event bus)
    # ------------------------------------------------------------------
    def _notify(self, alert: dict) -> None:
        if self._emit_callback is None:
            return
        try:
            self._emit_callback("alert", alert)
        except Exception as exc:
            logger.error(f"AlertManager: notification callback error: {exc}")

    def attach_emitter(self, callback: Callable[[str, Any], None]) -> None:
        """Attach a realtime emitter (e.g., socketio.emit)."""
        self._emit_callback = callback

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _fingerprint(
        detector: str,
        alert_type: str,
        source_ip: Optional[str],
        target_ip: Optional[str],
        source_mac: Optional[str] = None,
        target_mac: Optional[str] = None,
    ) -> str:
        key = "|".join(
            str(x or "") for x in (detector, alert_type, source_ip, target_ip, source_mac, target_mac)
        )
        return hashlib.md5(key.encode("utf-8")).hexdigest()

    @staticmethod
    def _normalize_severity(severity: Optional[str], details: dict) -> str:
        """Resolve a severity from explicit value or details; default medium."""
        candidate = severity or details.get("severity")
        if isinstance(candidate, str) and candidate.lower() in SEVERITY_RANK:
            return candidate.lower()
        return "medium"

    # ------------------------------------------------------------------
    # Introspection / stats
    # ------------------------------------------------------------------
    def cache_size(self) -> int:
        with self._lock:
            return len(self._cache)

    def dedupe_map_size(self) -> int:
        with self._lock:
            return len(self._last_seen)

    def health_dict(self) -> dict:
        return {
            "cache_size": self.cache_size(),
            "dedupe_map_size": self.dedupe_map_size(),
            "cooldown_seconds": self.cooldown_seconds,
            "emitter_attached": self._emit_callback is not None,
        }

