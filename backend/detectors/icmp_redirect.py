import scapy.all as scapy
import threading
import logging
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional

try:
    from core.alert_manager import AlertManager
except ImportError:
    AlertManager = None


class ICMPRedirectDetector:
    """ICMP Redirect Attack Detector.

    Detection logic is preserved exactly as-is. The detector no longer starts
    its own packet capture; it receives packets via ``handle_packet()``.
    """

    def __init__(self, interface: str = None, legitimate_gateways: List[str] = None):
        self.interface = interface
        self.legitimate_gateways = set(legitimate_gateways) if legitimate_gateways else set()
        self.redirect_sources = defaultdict(list)
        self.routing_table = {}
        self.is_running = False

        # Alert routing
        self.alert_manager = None
        self._alert_callback = None
        self._network_monitor = None

        self.logger = logging.getLogger(__name__)

        # Runtime metadata
        self._started_at = None
        self._packets_processed = 0
        self._alerts_generated = 0
        self._last_error = None
        self.monitor_thread = None

    # ------------------------------------------------------------------
    # AlertManager wiring
    # ------------------------------------------------------------------
    def set_alert_callback(self, callback) -> None:
        self._alert_callback = callback
        if AlertManager is not None:
            manager = getattr(callback, "__self__", None)
            if isinstance(manager, AlertManager):
                self.alert_manager = manager
        if self.alert_manager is None:
            self.alert_manager = callback

    def set_network_monitor(self, network_monitor) -> None:
        self._network_monitor = network_monitor

    # ------------------------------------------------------------------
    # Dispatcher entry point
    # ------------------------------------------------------------------
    def handle_packet(self, packet) -> None:
        if not self.is_running:
            return
        self._packets_processed += 1
        self.detect_icmp_redirect(packet)

    # ------------------------------------------------------------------
    # Detection logic (preserved unchanged)
    # ------------------------------------------------------------------
    def detect_icmp_redirect(self, packet):
        try:
            if packet.haslayer(scapy.ICMP):
                icmp_layer = packet[scapy.ICMP]
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst

                if icmp_layer.type == 5:
                    self._analyze_icmp_redirect(packet, src_ip, dst_ip, icmp_layer)
                elif icmp_layer.type in [0, 8]:
                    self._analyze_icmp_echo(packet, src_ip, dst_ip, icmp_layer)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in ICMP redirect detection: {e}")

    def _analyze_icmp_redirect(self, packet, src_ip: str, dst_ip: str, icmp_layer):
        try:
            redirect_code = icmp_layer.code

            redirect_types = {
                0: "Network Redirect",
                1: "Host Redirect",
                2: "TOS Network Redirect",
                3: "TOS Host Redirect"
            }

            redirect_type = redirect_types.get(redirect_code, "Unknown")

            if hasattr(icmp_layer, 'gw'):
                new_gateway = icmp_layer.gw
            else:
                if packet.haslayer(scapy.Raw):
                    payload = packet[scapy.Raw].load
                    if len(payload) >= 8:
                        new_gateway = ".".join(str(b) for b in payload[4:8])
                    else:
                        new_gateway = "unknown"
                else:
                    new_gateway = "unknown"

            redirect_info = {
                "timestamp": datetime.now(),
                "source_ip": src_ip,
                "target_ip": dst_ip,
                "redirect_type": redirect_type,
                "redirect_code": redirect_code,
                "new_gateway": new_gateway
            }

            self.redirect_sources[src_ip].append(redirect_info)

            cutoff_time = datetime.now() - timedelta(minutes=10)
            self.redirect_sources[src_ip] = [
                redirect for redirect in self.redirect_sources[src_ip]
                if redirect["timestamp"] > cutoff_time
            ]

            # --- Redirect source validation ---
            # Only the default gateway (or explicitly configured legitimate
            # gateways) may legitimately send ICMP redirects. Any other host
            # issuing a redirect is an attacker trying to hijack routing.
            #
            # IMPORTANT: if we have not yet resolved the gateway (legitimate_gateways
            # is empty AND _network_monitor.get_gateway() returns None), we CANNOT
            # determine legitimacy. In that case, skip the alert entirely to avoid
            # false positives during the startup / discovery window.
            source_is_legitimate = False
            gateway_is_known = False

            if self.legitimate_gateways and src_ip in self.legitimate_gateways:
                source_is_legitimate = True
                gateway_is_known = True
            else:
                # Fall back to the network monitor's known gateway if available.
                try:
                    if getattr(self, "_network_monitor", None) is not None:
                        gw = self._network_monitor.get_gateway()
                        if gw:
                            gateway_is_known = True
                            if src_ip == gw:
                                source_is_legitimate = True
                except Exception:
                    pass

            if gateway_is_known and not source_is_legitimate:
                # Per-source cooldown (5 minutes) to avoid alert spam.
                if not hasattr(self, "_icmp_redirect_cooldown"):
                    self._icmp_redirect_cooldown: Dict[str, datetime] = {}
                now_dt = datetime.now()
                last_alert = self._icmp_redirect_cooldown.get(src_ip)
                if last_alert is None or (now_dt - last_alert).total_seconds() > 300:
                    self._icmp_redirect_cooldown[src_ip] = now_dt
                    self._generate_alert("unauthorized_icmp_redirect", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "redirect_type": redirect_type,
                        "new_gateway": new_gateway,
                        "severity": "high",
                        "description": f"ICMP redirect from unauthorized source: {src_ip}"
                    })

            # --- New gateway legitimacy check ---
            # The offered gateway must be on the same subnet as the source
            # (a router only redirects within its own network) and must be a
            # private / link-local address, not a public IP.
            if new_gateway and new_gateway != "unknown":
                if not self._is_legitimate_gateway(src_ip, new_gateway):
                    self._generate_alert("rogue_gateway_redirect", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "new_gateway": new_gateway,
                        "redirect_type": redirect_type,
                        "severity": "critical",
                        "description": f"ICMP redirect to rogue gateway {new_gateway} from {src_ip}"
                    })

            if len(self.redirect_sources[src_ip]) > 10:
                self._generate_alert("excessive_icmp_redirects", {
                    "source_ip": src_ip,
                    "redirect_count": len(self.redirect_sources[src_ip]),
                    "time_window": "10 minutes",
                    "severity": "medium",
                    "description": f"Excessive ICMP redirects from {src_ip}"
                })

            self._detect_suspicious_gateway_changes(redirect_info)

            self.logger.info(f"ICMP Redirect: {src_ip} -> {dst_ip} via {new_gateway} ({redirect_type})")

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing ICMP redirect: {e}")

    def _is_legitimate_gateway(self, source_ip: str, new_gateway: str) -> bool:
        """Validate that the offered gateway is legitimate.

        A legitimate ICMP redirect should point to a host on the same subnet
        as the source (the router), and should be a private or link-local
        address rather than a public IP.
        """
        try:
            # Link-local addresses are used on some home/office networks.
            if new_gateway.startswith("169.254."):
                return True

            # The gateway should be a private IP (same LAN).
            is_private = (
                new_gateway.startswith("192.168.") or
                new_gateway.startswith("10.") or
                new_gateway.startswith("172.")
            )
            if not is_private:
                return False

            # The gateway should be on the same /24 subnet as the source.
            try:
                from ipaddress import ip_address
                src_int = int(ip_address(source_ip))
                gw_int = int(ip_address(new_gateway))
                if (src_int >> 8) == (gw_int >> 8):
                    return True
            except Exception:
                pass

            # If subnet comparison fails, still allow private gateways.
            return True
        except Exception:
            return True

    def _analyze_icmp_echo(self, packet, src_ip: str, dst_ip: str, icmp_layer):
        try:
            echo_type = "Echo Request" if icmp_layer.type == 8 else "Echo Reply"

            if not hasattr(self, 'echo_patterns'):
                self.echo_patterns = defaultdict(list)

            current_time = datetime.now()
            self.echo_patterns[src_ip].append({
                "timestamp": current_time,
                "target_ip": dst_ip,
                "echo_type": echo_type
            })

            cutoff_time = current_time - timedelta(minutes=5)
            self.echo_patterns[src_ip] = [
                echo for echo in self.echo_patterns[src_ip]
                if echo["timestamp"] > cutoff_time
            ]

            if len(self.echo_patterns[src_ip]) > 20:
                unique_targets = set(echo["target_ip"] for echo in self.echo_patterns[src_ip])
                if len(unique_targets) > 10:
                    self._generate_alert("icmp_ping_sweep", {
                        "source_ip": src_ip,
                        "target_count": len(unique_targets),
                        "total_pings": len(self.echo_patterns[src_ip]),
                        "severity": "low",
                        "description": f"Potential ICMP ping sweep from {src_ip}"
                    })

        except Exception as e:
            self.logger.error(f"Error analyzing ICMP echo: {e}")

    def _detect_suspicious_gateway_changes(self, redirect_info: Dict):
        try:
            target_ip = redirect_info["target_ip"]
            new_gateway = redirect_info["new_gateway"]
            source_ip = redirect_info["source_ip"]

            if target_ip in self.routing_table:
                old_gateway = self.routing_table[target_ip]
                if old_gateway != new_gateway:
                    self._generate_alert("gateway_change_detected", {
                        "target_ip": target_ip,
                        "old_gateway": old_gateway,
                        "new_gateway": new_gateway,
                        "redirect_source": source_ip,
                        "severity": "medium",
                        "description": f"Gateway changed for {target_ip}: {old_gateway} -> {new_gateway}"
                    })

            self.routing_table[target_ip] = new_gateway

            if (target_ip.startswith(('192.168.', '10.', '172.')) and
                not new_gateway.startswith(('192.168.', '10.', '172.'))):

                self._generate_alert("private_to_public_redirect", {
                    "target_ip": target_ip,
                    "new_gateway": new_gateway,
                    "redirect_source": source_ip,
                    "severity": "high",
                    "description": f"Private IP {target_ip} redirected to external gateway {new_gateway}"
                })

        except Exception as e:
            self.logger.error(f"Error detecting suspicious gateway changes: {e}")

    # ------------------------------------------------------------------
    # Alert routing
    # ------------------------------------------------------------------
    def _generate_alert(self, alert_type: str, details: Dict):
        try:
            source_ip = details.get("source_ip")
            target_ip = details.get("target_ip")
            severity = details.get("severity", "medium")
            description = details.get("description")

            if self._alert_callback is not None:
                self._alert_callback(
                    detector="icmp_redirect",
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
                    "detector": "icmp_redirect",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"ICMP Redirect Alert: {alert}")

            if getattr(self, "_network_monitor", None) is not None and source_ip:
                try:
                    self._network_monitor.record_suspicious(source_ip, alert_type)
                except Exception:
                    pass

            return details
        except Exception as e:
            self.logger.error(f"Error generating ICMP alert: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting ICMP redirect detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        self.is_running = False
        self.logger.info("Stopping ICMP redirect detector")

    def status(self) -> str:
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        return {
            "detector": "icmp_redirect",
            "status": self.status(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "uptime_seconds": int((datetime.utcnow() - self._started_at).total_seconds())
            if self._started_at else 0,
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "last_error": self._last_error,
            "thread_alive": bool(self.monitor_thread and self.monitor_thread.is_alive()),
            "routing_table_size": len(self.routing_table),
        }

    def get_thread(self) -> Optional[threading.Thread]:
        return self.monitor_thread

    def statistics(self) -> dict:
        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "routing_table_size": len(self.routing_table),
            "redirect_sources": len(self.redirect_sources),
        }

    def start_monitoring(self):
        self.start()

    def stop_monitoring(self):
        self.stop()
