import scapy.all as scapy
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Optional

# Conditional import so the module can be imported in environments / unit
# tests where the core engine is not yet wired (keeps backward compatibility).
try:
    from core.alert_manager import AlertManager
except ImportError:  # pragma: no cover - standalone usage
    AlertManager = None


class ARPSpoofDetector:
    """ARP Spoofing Attack Detector.

    Alerts are generated ONLY for confirmed attack signals:
      1. IP-MAC conflict: an ARP reply maps an IP to a different MAC than
         what was previously observed.
      2. Gateway MAC change: the default-gateway IP answers with a new MAC.
      3. Gratuitous ARP (op=2, src_ip==dst_ip) WITH a MAC conflict vs the
         ARP table — normal gratuitous ARPs (unchanged MAC) are silently
         ignored.

    HIGH ARP FREQUENCY IS NOT AN ATTACK INDICATOR and is intentionally
    absent.  Wi-Fi networks naturally generate frequent ARP traffic due to
    DHCP renewal, device wake-up, OS background probing, and broadcast
    discovery.  Treating frequency as an attack causes constant false
    positives on every healthy network.

    The detector no longer starts its own packet capture; it receives
    packets via ``handle_packet()`` which is called by the shared
    ``PacketDispatcher``.
    """

    def __init__(self, interface: str = None, threshold: int = 10, time_window: int = 60):
        self.interface = interface
        # threshold / time_window kept for backward-compat; no longer used
        # to generate alerts.
        self.threshold = threshold
        self.time_window = time_window
        self.arp_table: Dict[str, str] = {}   # IP -> MAC (ground truth)
        self.gateway_ip: Optional[str] = None
        self.gateway_mac: Optional[str] = None
        self.suspicious_ips: set = set()
        self.is_running = False

        # Alert routing: set by the factory / MonitoringManager.
        self.alert_manager = None
        self._alert_callback = None

        self.logger = logging.getLogger(__name__)

        # Runtime metadata for status()/health()
        self._started_at: Optional[datetime] = None
        self._packets_processed = 0
        self._alerts_generated = 0
        self._last_error: Optional[str] = None
        # The dispatcher owns the real thread; this references it for health checks.
        self.monitor_thread: Optional[threading.Thread] = None

    # ------------------------------------------------------------------
    # AlertManager wiring (called by MonitoringManager.register_detector)
    # ------------------------------------------------------------------
    def set_alert_callback(self, callback) -> None:
        """Attach the AlertManager callback so alerts reach the DB + WebSocket."""
        self._alert_callback = callback
        if AlertManager is not None:
            manager = getattr(callback, "__self__", None)
            if isinstance(manager, AlertManager):
                self.alert_manager = manager
        if self.alert_manager is None:
            self.alert_manager = callback

    def set_network_monitor(self, network_monitor) -> None:
        """Register the network monitor so suspicious devices get risk scores."""
        self._network_monitor = network_monitor
        try:
            self.gateway_ip = network_monitor.get_gateway()
        except Exception:
            pass

    def _check_gateway_mac(self, src_ip: str, src_mac: str) -> None:
        """Alert when the default gateway MAC changes (classic MITM indicator)."""
        if not self.gateway_ip:
            if getattr(self, "_network_monitor", None):
                self.gateway_ip = self._network_monitor.get_gateway()
        if not self.gateway_ip or src_ip != self.gateway_ip:
            return
        if self.gateway_mac is None:
            self.gateway_mac = src_mac
            return
        if self.gateway_mac != src_mac:
            self._generate_alert("gateway_mac_change", {
                "source_ip": src_ip,
                "original_mac": self.gateway_mac,
                "spoofed_mac": src_mac,
                "severity": "critical",
                "description": (
                    f"Default gateway MAC address changed from {self.gateway_mac} "
                    f"to {src_mac} — possible ARP MITM"
                ),
            })
            self.gateway_mac = src_mac

    # ------------------------------------------------------------------
    # Dispatcher entry point
    # ------------------------------------------------------------------
    def handle_packet(self, packet) -> None:
        """Called by PacketDispatcher for every captured packet."""
        if not self.is_running:
            return
        self._packets_processed += 1
        self.detect_arp_spoof(packet)

    # ------------------------------------------------------------------
    # Detection logic
    # ------------------------------------------------------------------
    def get_mac_address(self, ip: str) -> Optional[str]:
        """Get MAC address for given IP from the passively-learned ARP table.

        Non-blocking: never sends an ARP request.  The ARP table is
        populated by observed ARP replies during normal packet capture.
        """
        try:
            return self.arp_table.get(ip)
        except Exception as e:
            self.logger.error(f"Error getting MAC for {ip}: {e}")
            return None

    def detect_arp_spoof(self, packet):
        """Analyze ARP packet for real spoofing indicators ONLY.

        Checks performed:
          • op=2 reply with IP-MAC conflict vs. stored ARP table entry.
          • op=2 from gateway IP with a changed MAC (gateway_mac_change).
          • op=2 gratuitous ARP (src_ip == dst_ip) AND MAC differs from
            the stored entry — normal gratuitous ARPs are silently ignored.

        NOT checked (intentionally absent):
          • ARP request frequency — this is NORMAL Wi-Fi behavior and
            MUST NEVER generate an alert regardless of packet rate.
        """
        try:
            if not packet.haslayer(scapy.ARP):
                return

            arp_layer = packet[scapy.ARP]
            src_ip  = arp_layer.psrc
            src_mac = arp_layer.hwsrc
            dst_ip  = arp_layer.pdst
            op_code = arp_layer.op

            # ── op=1 (ARP Request) ──────────────────────────────────────
            # Passively seed the ARP table; never generate an alert.
            if op_code == 1:
                if src_ip and src_mac and src_ip not in self.arp_table:
                    self.arp_table[src_ip] = src_mac
                return

            # ── op=2 (ARP Reply) ────────────────────────────────────────
            if op_code == 2:
                # 1. Gateway MAC change (highest priority check).
                self._check_gateway_mac(src_ip, src_mac)

                is_gratuitous = (src_ip == dst_ip)

                if src_ip in self.arp_table:
                    stored_mac = self.arp_table[src_ip]
                    if stored_mac != src_mac:
                        # ── Real IP-MAC conflict ─────────────────────────
                        if is_gratuitous:
                            # Gratuitous ARP with conflicting MAC — alert.
                            # Normal gratuitous ARPs (same MAC) are ignored.
                            self._generate_alert("gratuitous_arp_spoof", {
                                "source_ip": src_ip,
                                "original_mac": stored_mac,
                                "spoofed_mac": src_mac,
                                "severity": "high",
                                "description": (
                                    f"Gratuitous ARP from {src_ip} announced a new MAC "
                                    f"({src_mac}, was {stored_mac}) — possible ARP poisoning"
                                ),
                            })
                        else:
                            self._generate_alert("arp_spoofing", {
                                "source_ip": src_ip,
                                "original_mac": stored_mac,
                                "spoofed_mac": src_mac,
                                "target_ip": dst_ip,
                                "severity": "high",
                                "description": (
                                    f"MAC address conflict: {src_ip} was "
                                    f"{stored_mac}, now claims {src_mac}"
                                ),
                            })
                        self.suspicious_ips.add(src_ip)
                        # Update so subsequent packets don't double-alert.
                        self.arp_table[src_ip] = src_mac
                else:
                    # First-seen IP/MAC pair — record as ground truth.
                    self.arp_table[src_ip] = src_mac

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in ARP spoof detection: {e}")

    def _generate_alert(self, alert_type: str, details: Dict):
        """Send alert to AlertManager instead of only logging it."""
        try:
            source_ip = details.get("source_ip")
            target_ip = details.get("target_ip")
            severity  = details.get("severity", "medium")
            description = details.get("description")

            if self._alert_callback is not None:
                self._alert_callback(
                    detector="arp_spoof",
                    alert_type=alert_type,
                    details=details,
                    severity=severity,
                    source_ip=source_ip,
                    target_ip=target_ip,
                )
                self._alerts_generated += 1
            else:
                alert = {
                    "timestamp": datetime.now().isoformat(),
                    "detector": "arp_spoof",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"ARP Spoofing Alert: {alert}")

            # Provide risk-score feedback to the network monitor.
            if getattr(self, "_network_monitor", None) is not None and source_ip:
                try:
                    self._network_monitor.record_suspicious(source_ip, alert_type)
                except Exception:
                    pass

            return details
        except Exception as e:
            self.logger.error(f"Error generating ARP alert: {e}")

    # ------------------------------------------------------------------
    # Lifecycle: dispatcher-compatible API
    # ------------------------------------------------------------------
    def start(self) -> None:
        """Mark the detector as running (packets arrive from the dispatcher)."""
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting ARP spoofing detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        """Stop the detector (no more packets processed)."""
        self.is_running = False
        self.logger.info("Stopping ARP spoofing detector")

    def status(self) -> str:
        """Return detector status string ('running'|'stopped'|'error')."""
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        """Return live health metrics for the detector."""
        return {
            "detector": "arp_spoof",
            "status": self.status(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "uptime_seconds": int((datetime.utcnow() - self._started_at).total_seconds())
            if self._started_at else 0,
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "suspicious_ips": len(self.suspicious_ips),
            "arp_table_size": len(self.arp_table),
            "last_error": self._last_error,
            "thread_alive": bool(self.monitor_thread and self.monitor_thread.is_alive()),
            "threshold": self.threshold,
            "time_window": self.time_window,
        }

    def get_thread(self) -> Optional[threading.Thread]:
        """Return the detector's thread (for MonitoringManager health checks)."""
        return self.monitor_thread

    def statistics(self) -> dict:
        """Return detector-level statistics (runtime counters)."""
        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "suspicious_ips": list(self.suspicious_ips),
            "arp_table_size": len(self.arp_table),
        }

    # ------------------------------------------------------------------
    # Backward-compatible API (kept so legacy callers still work)
    # ------------------------------------------------------------------
    def start_monitoring(self):
        """Legacy alias for start()."""
        self.start()

    def stop_monitoring(self):
        """Legacy alias for stop()."""
        self.stop()
