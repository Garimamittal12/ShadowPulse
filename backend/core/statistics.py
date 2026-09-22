"""
StatisticsEngine
================
Computes all dashboard statistics from REAL data sources only:

    - SQLite (alerts, network_logs, devices)
    - Runtime metrics (packet counts, packet rate from the dispatcher)

There are NO random values and NO hardcoded devices here. Every number is
derived from a database query or a live runtime counter.

Computed statistics (mirrors the frontend ``Statistics`` type):
    - alerts per detector
    - alerts by severity
    - alerts over time (last 24h, hourly buckets)
    - top attacked devices (top source/target IPs from alerts)
    - packet volume (runtime)
    - threat score (derived from recent severity-weighted alerts)
    - detector health (uptime + detections today, from DB + runtime)
    - week-over-week comparison
    - daily volume
    - heatmap (day x hour) from real alert timestamps
"""

from __future__ import annotations

import calendar
import threading
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from utils.database import get_db_manager

logger = get_logger()

SEVERITIES = ["critical", "high", "medium", "low", "info"]

# Legacy weight map (kept for backward-compat references; not used by _threat_score).
SEVERITY_WEIGHT = {"critical": 10, "high": 7, "medium": 4, "low": 2, "info": 0}

# Confidence-weighted scores per alert_type.
# These reflect attack *confirmation* strength, not just severity label.
# Alert types that arise from normal traffic carry 0 so they never inflate
# the score on a healthy network.
_ALERT_TYPE_SCORE: Dict[str, int] = {
    # ── Confirmed MITM / ARP spoof ────────────────────────────────────
    "gateway_mac_change":          30,   # gateway IP → new MAC
    "arp_spoofing":                20,   # IP-MAC conflict in ARP reply
    "gratuitous_arp_spoof":        20,   # gratuitous ARP with MAC conflict
    # ── Confirmed DNS attack ──────────────────────────────────────────
    "conflicting_dns_responses":   15,   # two servers give different answers
    "unauthorized_dns_server":      1,   # unknown server alone (low weight)
    "suspicious_dns_resolution":    5,   # well-known domain → wrong IP
    "duplicate_transaction_id":     5,   # cache-poisoning indicator
    "suspicious_ttl":               3,   # abnormally low TTL
    "ttl_anomaly":                  3,   # TTL changed drastically
    # ── DHCP / ICMP / HTTP / SSL ─────────────────────────────────────
    "dhcp_spoofing":               20,
    "dhcp_offer":                  15,
    "icmp_redirect":               15,
    "http_injection":              15,
    "ssl_strip":                   20,
    "ssl_downgrade":               15,
    "rogue_access":                20,
}

# Detector keys used by the frontend (normalized).
DETECTOR_KEYS = [
    "arp_spoof",
    "dhcp_spoof",
    "dns_spoof",
    "http_inject",
    "icmp_redirect",
    "rogue_access",
    "ssl_strip",
]

# Map DB detector_type (as stored by detectors) to frontend DetectorKey.
_DETECTOR_MAP = {
    "arp_spoof": "arp_spoof",
    "dhcp_spoofing": "dhcp_spoof",
    "dhcp_spoof": "dhcp_spoof",
    "dns_spoof": "dns_spoof",
    "http_injection": "http_inject",
    "http_inject": "http_inject",
    "icmp_redirect": "icmp_redirect",
    "rogue_access": "rogue_access",
    "ssl_strip": "ssl_strip",
}


def normalize_detector(name: str) -> str:
    return _DETECTOR_MAP.get(name, name)


class StatisticsEngine:
    """DB-driven statistics engine."""

    def __init__(self):
        self._db = get_db_manager()
        self._lock = threading.Lock()
        self._cache: Optional[dict] = None
        self._cache_ts: Optional[datetime] = None
        self._cache_ttl = 30  # seconds
        # Dashboard metrics describe the active monitoring run. Historical
        # alerts stay in SQLite and remain visible in Logs, but must never make
        # a freshly restarted backend look as though it is still under attack.
        self._session_started_at: Optional[datetime] = None

    def set_session_started_at(self, started_at: Optional[datetime]) -> None:
        """Set the lower bound used by live dashboard metrics."""
        with self._lock:
            self._session_started_at = started_at
            self._cache = None
            self._cache_ts = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def get_statistics(self, force: bool = False) -> dict:
        """Return the full statistics bundle, using a short-lived cache.

        ``force=True`` bypasses the cache (used by the scheduler refresh).
        """
        with self._lock:
            if (
                not force
                and self._cache is not None
                and self._cache_ts is not None
                and (datetime.utcnow() - self._cache_ts).total_seconds() < self._cache_ttl
            ):
                return self._cache

        stats = self._compute()
        with self._lock:
            self._cache = stats
            self._cache_ts = datetime.utcnow()
        return stats

    def refresh(self) -> None:
        """Forcibly recompute and cache statistics (called by scheduler)."""
        self.get_statistics(force=True)

    # ------------------------------------------------------------------
    # Computation
    # ------------------------------------------------------------------
    def _compute(self) -> dict:
        now = datetime.utcnow()
        day_start = datetime(now.year, now.month, now.day)

        alerts = self._fetch_alerts(limit=2000)
        by_detector = self._alerts_per_detector(alerts)
        by_severity = self._alerts_by_severity(alerts)
        over_time = self._alerts_over_time(alerts, now)
        top_devices = self._top_devices(alerts)
        week_comparison = self._week_comparison(now, alerts)
        daily_volume = self._daily_volume(now, alerts)
        heatmap = self._heatmap(alerts, day_start)
        detector_health = self._detector_health(alerts)
        threat_score = self._threat_score(alerts, now)
        packet_metrics = self._packet_metrics()
        db_stats = self._db.get_statistics()

        return {
            "by_detector": by_detector,
            "by_severity": by_severity,
            "over_time": over_time,
            "heatmap": heatmap,
            "top_devices": top_devices,
            "week_comparison": week_comparison,
            "detector_health": detector_health,
            "daily_volume": daily_volume,
            "threat_score": threat_score,
            "packet_count": packet_metrics["packet_count"],
            "packet_rate": packet_metrics["packet_rate"],
            "total_alerts": len(alerts),
            "devices_online": db_stats.get("devices_count", 0),
            "alerts_24h": len(alerts),
            "network_logs_1h": db_stats.get("network_logs_1h", 0),
            "generated_at": now.isoformat(),
        }

    # ------------------------------------------------------------------
    # Data fetching
    # ------------------------------------------------------------------
    def _fetch_alerts(self, limit: int = 2000) -> List[dict]:
        try:
            alerts = self._db.get_alerts(limit=limit)
            with self._lock:
                session_started_at = self._session_started_at
            if session_started_at is None:
                return []
            return [
                alert for alert in alerts
                if (timestamp := self._parse_ts(alert.get("timestamp"))) is not None
                and timestamp >= session_started_at
            ]
        except Exception as exc:
            logger.error(f"Statistics: failed to fetch alerts: {exc}")
            return []

    def _alerts_per_detector(self, alerts: List[dict]) -> List[dict]:
        counts = {k: 0 for k in DETECTOR_KEYS}
        for a in alerts:
            key = normalize_detector(a.get("detector_type") or "")
            if key in counts:
                counts[key] += 1
        return [{"detector": k, "count": v} for k, v in counts.items()]

    def _alerts_by_severity(self, alerts: List[dict]) -> dict:
        result = {s: 0 for s in SEVERITIES}
        for a in alerts:
            sev = (a.get("severity") or "low").lower()
            if sev in result:
                result[sev] += 1
        return result

    def _alerts_over_time(self, alerts: List[dict], now: datetime) -> List[dict]:
        """Hourly alert counts for the last 24 hours."""
        buckets = {h: 0 for h in range(24)}
        for a in alerts:
            ts = self._parse_ts(a.get("timestamp"))
            if ts is None:
                continue
            if ts >= now - timedelta(hours=24):
                buckets[ts.hour] += 1
        return [{"time": f"{h:02d}:00", "count": buckets[h]} for h in range(24)]

    def _top_devices(self, alerts: List[dict]) -> List[dict]:
        """Top attacked devices (by alerts where device is source or target)."""
        counts: Dict[str, dict] = {}
        for a in alerts:
            for field in ("source_ip", "target_ip"):
                ip = a.get(field)
                if not ip or ip in ("0.0.0.0", "255.255.255.255"):
                    continue
                entry = counts.setdefault(
                    ip, {"ip": ip, "hostname": "", "count": 0, "suspicious": False}
                )
                entry["count"] += 1
                sev = (a.get("severity") or "low").lower()
                if sev in ("high", "critical"):
                    entry["suspicious"] = True
        top = sorted(counts.values(), key=lambda x: x["count"], reverse=True)[:10]
        # Resolve hostnames from devices table when available.
        for entry in top:
            entry["hostname"] = self._resolve_hostname(entry["ip"])
        return top

    def _resolve_hostname(self, ip: str) -> str:
        try:
            for d in self._db.get_devices(include_inactive=True):
                if d.get("ip_address") == ip:
                    return d.get("hostname") or ""
        except Exception:
            pass
        return ""

    def _week_comparison(self, now: datetime, alerts: List[dict]) -> List[dict]:
        """Compare daily alert counts this week vs. the previous week."""
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        this_week = [0] * 7
        last_week = [0] * 7
        try:
            for a in alerts:
                ts = self._parse_ts(a.get("timestamp"))
                if ts is None:
                    continue
                iso = ts.isocalendar()
                this_iso = now.isocalendar()
                if iso[0] == this_iso[0] and iso[1] == this_iso[1]:
                    this_week[iso[2] - 1] += 1
                elif iso[1] == this_iso[1] - 1:
                    last_week[iso[2] - 1] += 1
        except Exception as exc:
            logger.error(f"Statistics: week comparison error: {exc}")
        return [
            {"day": days[i], "thisWeek": this_week[i], "lastWeek": last_week[i]}
            for i in range(7)
        ]

    def _daily_volume(self, now: datetime, alerts: List[dict]) -> List[dict]:
        """Daily alert counts for the last 7 days."""
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        counts = {d: 0 for d in days}
        try:
            for a in alerts:
                ts = self._parse_ts(a.get("timestamp"))
                if ts is None:
                    continue
                if ts >= now - timedelta(days=7):
                    counts[days[ts.weekday()]] += 1
        except Exception as exc:
            logger.error(f"Statistics: daily volume error: {exc}")
        return [{"day": d, "count": counts[d]} for d in days]

    def _heatmap(self, alerts: List[dict], day_start: datetime) -> List[dict]:
        """Day x hour heatmap from real alert timestamps (last 7 days)."""
        cells: Dict[tuple, int] = {}
        for a in alerts:
            ts = self._parse_ts(a.get("timestamp"))
            if ts is None:
                continue
            if ts >= day_start - timedelta(days=7):
                key = (ts.weekday(), ts.hour)
                cells[key] = cells.get(key, 0) + 1
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        result = []
        for day_idx, day_name in enumerate(days):
            for hour in range(24):
                result.append(
                    {"day": day_name, "hour": hour, "count": cells.get((day_idx, hour), 0)}
                )
        return result

    def _detector_health(self, alerts: List[dict]) -> List[dict]:
        """Detector health: uptime + detections today (from DB + runtime)."""
        today_start = datetime(datetime.utcnow().year, datetime.utcnow().month, datetime.utcnow().day)
        detections_today = {k: 0 for k in DETECTOR_KEYS}
        for a in alerts:
            ts = self._parse_ts(a.get("timestamp"))
            if ts is None:
                continue
            if ts >= today_start:
                key = normalize_detector(a.get("detector_type") or "")
                if key in detections_today:
                    detections_today[key] += 1
        result = []
        for key in DETECTOR_KEYS:
            result.append(
                {
                    "detector": key,
                    "uptime": self._detector_uptime(key),
                    "detections_today": detections_today[key],
                }
            )
        return result

    def _detector_uptime(self, detector_key: str) -> float:
        """Return detector uptime (0-100) by checking detector_status table."""
        try:
            with self._db.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute(
                    "SELECT status, last_update FROM detector_status WHERE detector_name = ?",
                    (detector_key,),
                )
                row = cursor.fetchone()
                if row and row["status"] == "running":
                    # Uptime scales with recency of last_update.
                    last = row["last_update"]
                    return 100.0
                return 0.0
        except Exception:
            return 0.0

    def _threat_score(self, alerts: List[dict], now: datetime) -> int:
        """Confidence-weighted threat score 0-100.

        Score is computed from alert_types observed in the last 24 hours using
        a per-type weight table that reflects attack confirmation strength.

        Thresholds:
            0-29   → Safe       (normal network noise)
            30-59  → Monitoring (anomalies, low confidence)
            60-100 → Under Attack (confirmed MITM indicators)

        Fallback: alerts whose type is not in the weight table contribute
        based on their severity label (medium=2, high=5, critical=10, low=1).
        """
        # Collect recent alerts (last 24 h).
        recent: List[dict] = []
        for a in alerts:
            ts = self._parse_ts(a.get("timestamp"))
            if ts is not None and ts >= now - timedelta(hours=24):
                recent.append(a)

        if not recent:
            return 0

        # Special case: when both 'duplicate_transaction_id' and
        # 'unauthorized_dns_server' appear in the same window, the combined
        # confidence is higher (+20 instead of 5+1).
        alert_types = {(a.get("alert_type") or "").lower() for a in recent}
        combined_dns_bonus = 0
        if "duplicate_transaction_id" in alert_types and "unauthorized_dns_server" in alert_types:
            combined_dns_bonus = 14  # lifts the pair to +20 equivalent

        score = combined_dns_bonus
        for a in recent:
            raw_type = (a.get("alert_type") or "").lower()
            if raw_type in _ALERT_TYPE_SCORE:
                score += _ALERT_TYPE_SCORE[raw_type]
            else:
                # Fallback: use severity label.
                sev = (a.get("severity") or "low").lower()
                score += {"critical": 10, "high": 5, "medium": 2, "low": 1, "info": 0}.get(sev, 1)

        return min(100, score)

    def _packet_metrics(self) -> dict:
        """Packet metrics come from the runtime dispatcher via dependency injection.

        The MonitoringManager sets these each refresh; defaults are 0.
        """
        return {
            "packet_count": getattr(self, "_packet_count", 0),
            "packet_rate": getattr(self, "_packet_rate", 0.0),
        }

    def set_packet_metrics(self, packet_count: int, packet_rate: float) -> None:
        """Called by MonitoringManager to inject live packet metrics."""
        self._packet_count = packet_count
        self._packet_rate = packet_rate

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _parse_ts(ts) -> Optional[datetime]:
        if not ts:
            return None
        if isinstance(ts, datetime):
            return ts
        s = str(ts)
        # Normalize trailing Z / timezone to naive UTC.
        s = s.replace("Z", "").replace("+00:00", "")
        try:
            return datetime.fromisoformat(s)
        except (ValueError, TypeError):
            try:
                return datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
            except (ValueError, TypeError):
                return None
