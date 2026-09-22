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


class DHCPSpoofingDetector:
    """DHCP Spoofing Attack Detector.

    Detection logic is preserved exactly as-is. The detector no longer starts
    its own packet capture; it receives packets via ``handle_packet()``.
    """

    def __init__(self, interface: str = None, authorized_servers: List[str] = None):
        self.interface = interface
        self.authorized_servers = set(authorized_servers) if authorized_servers else set()
        self.dhcp_servers = {}
        self.dhcp_offers = defaultdict(list)
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
        self.detect_dhcp_spoofing(packet)

    # ------------------------------------------------------------------
    # Detection logic (preserved unchanged)
    # ------------------------------------------------------------------
    def detect_dhcp_spoofing(self, packet):
        try:
            if packet.haslayer(scapy.DHCP):
                dhcp_layer = packet[scapy.DHCP]
                dhcp_options = {}
                for option in dhcp_layer.options:
                    if isinstance(option, tuple) and len(option) == 2:
                        dhcp_options[option[0]] = option[1]

                message_type = dhcp_options.get('message-type')
                server_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
                server_mac = packet[scapy.Ether].src if packet.haslayer(scapy.Ether) else None

                if message_type == 2:
                    self._analyze_dhcp_offer(packet, server_ip, server_mac, dhcp_options)
                elif message_type == 5:
                    self._analyze_dhcp_ack(packet, server_ip, server_mac, dhcp_options)

                if server_ip and server_mac and message_type in [2, 5]:
                    if server_mac in self.dhcp_servers:
                        if self.dhcp_servers[server_mac] != server_ip:
                            self._generate_alert("dhcp_server_ip_change", {
                                "server_mac": server_mac,
                                "old_ip": self.dhcp_servers[server_mac],
                                "new_ip": server_ip,
                                "severity": "medium"
                            })
                    else:
                        self.dhcp_servers[server_mac] = server_ip
                        # Only alert on unauthorized DHCP server when an explicit
                        # authorized_servers list has been configured. Without a
                        # whitelist we cannot determine what is "authorized", so
                        # alerting on every new DHCP server generates false positives
                        # on any network with a legitimate DHCP server.
                        if self.authorized_servers and server_ip not in self.authorized_servers:
                            self._generate_alert("unauthorized_dhcp_server", {
                                "server_ip": server_ip,
                                "server_mac": server_mac,
                                "severity": "high",
                                "description": "Unauthorized DHCP server detected"
                            })
        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in DHCP spoof detection: {e}")

    def _analyze_dhcp_offer(self, packet, server_ip: str, server_mac: str, options: Dict):
        try:
            offered_ip = packet[scapy.BOOTP].yiaddr
            subnet_mask = options.get('subnet_mask')
            router = options.get('router')
            dns_servers = options.get('name_server')

            offer_info = {
                "timestamp": datetime.now(),
                "server_ip": server_ip,
                "server_mac": server_mac,
                "offered_ip": offered_ip,
                "subnet_mask": subnet_mask,
                "router": router,
                "dns_servers": dns_servers
            }

            client_mac = packet[scapy.Ether].dst
            self.dhcp_offers[client_mac].append(offer_info)

            cutoff_time = datetime.now() - timedelta(minutes=5)
            self.dhcp_offers[client_mac] = [
                offer for offer in self.dhcp_offers[client_mac]
                if offer["timestamp"] > cutoff_time
            ]

            # Memory bounds: cap the number of tracked client MACs. When the
            # cap is exceeded, drop the oldest-timestamp client entries so the
            # structure cannot grow unbounded on a busy network.
            if len(self.dhcp_offers) > 500:
                # Sort client MACs by their most recent offer timestamp.
                oldest_first = sorted(
                    self.dhcp_offers.items(),
                    key=lambda kv: max(
                        (o.get("timestamp", datetime.min) for o in kv[1]),
                        default=datetime.min,
                    ),
                )
                # Remove the oldest entries until we're back under the cap.
                for mac, _ in oldest_first:
                    if len(self.dhcp_offers) <= 500:
                        break
                    del self.dhcp_offers[mac]

            unique_servers = set()
            for offer in self.dhcp_offers[client_mac]:
                unique_servers.add(offer["server_mac"])

            if len(unique_servers) > 1:
                self._generate_alert("multiple_dhcp_offers", {
                    "client_mac": client_mac,
                    "server_count": len(unique_servers),
                    "servers": list(unique_servers),
                    "severity": "high",
                    "description": "Multiple DHCP servers responding to same client"
                })

            self._detect_suspicious_config(offer_info)
        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing DHCP offer: {e}")

    def _analyze_dhcp_ack(self, packet, server_ip: str, server_mac: str, options: Dict):
        try:
            assigned_ip = packet[scapy.BOOTP].yiaddr
            client_mac = packet[scapy.Ether].dst
            self.logger.info(f"DHCP assignment: {assigned_ip} -> {client_mac} via {server_ip}")
        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing DHCP ACK: {e}")

    def _detect_suspicious_config(self, offer_info: Dict):
        try:
            dns_servers = offer_info.get("dns_servers")
            if dns_servers:
                # Normalize to a list of IP strings.
                if isinstance(dns_servers, bytes):
                    dns_servers = [dns_servers.decode("utf-8", errors="ignore")]
                elif isinstance(dns_servers, str):
                    dns_servers = [dns_servers]
                elif not isinstance(dns_servers, (list, tuple)):
                    dns_servers = [str(dns_servers)]

                # Rogue DNS detection: a DHCP server offering a PUBLIC-IP DNS
                # that is not a well-known resolver is suspicious.
                #
                # IMPORTANT: Private-IP DNS servers (192.168.x.x, 10.x.x.x,
                # 172.16-31.x.x) are COMPLETELY NORMAL in home, corporate, and
                # ISP environments. The gateway router typically acts as a
                # DNS proxy/forwarder and offers its own LAN IP as the DNS server.
                # We must NOT alert on private-IP DNS servers.
                well_known_dns = {
                    "8.8.8.8", "8.8.4.4",
                    "1.1.1.1", "1.0.0.1",
                    "208.67.222.222", "208.67.220.220",
                    "9.9.9.9", "149.112.112.112",
                }
                for dns in dns_servers:
                    dns_str = str(dns).strip()
                    if not dns_str:
                        continue
                    # Skip private-IP DNS — normal router/corporate behavior.
                    _is_private_dns = (
                        dns_str.startswith('192.168.') or
                        dns_str.startswith('10.') or
                        dns_str.startswith('169.254.') or
                        dns_str.startswith('172.')
                    )
                    if _is_private_dns:
                        continue
                    # Alert only when the offered DNS is a PUBLIC IP not in
                    # the well-known set — this is a genuine rogue indicator.
                    if dns_str not in well_known_dns:
                        self._generate_alert("rogue_dns_server", {
                            "server_ip": offer_info.get("server_ip"),
                            "server_mac": offer_info.get("server_mac"),
                            "dns_server": dns_str,
                            "severity": "high",
                            "description": f"DHCP offering unknown PUBLIC DNS server: {dns_str} - possible rogue AP"
                        })

            router = offer_info.get("router")
            if router:
                # Normalize router to a list of IP strings.
                if isinstance(router, bytes):
                    router = [router.decode("utf-8", errors="ignore")]
                elif isinstance(router, str):
                    router = [router]
                elif not isinstance(router, (list, tuple)):
                    router = [str(router)]

                # Rogue gateway detection: the offered router should be on the
                # same subnet as the offered IP, and should not be a public IP.
                offered_ip = offer_info.get("offered_ip", "")
                for gw in router:
                    gw_str = str(gw).strip()
                    if not gw_str:
                        continue
                    # A public IP as the default gateway is a strong indicator.
                    if not (gw_str.startswith("192.168.") or
                            gw_str.startswith("10.") or
                            gw_str.startswith("172.")):
                        self._generate_alert("rogue_gateway", {
                            "server_ip": offer_info.get("server_ip"),
                            "server_mac": offer_info.get("server_mac"),
                            "gateway": gw_str,
                            "offered_ip": offered_ip,
                            "severity": "critical",
                            "description": f"DHCP offering rogue gateway: {gw_str}"
                        })
                    # Gateway should be in the same subnet as the offered IP.
                    elif offered_ip and not self._same_subnet(offered_ip, gw_str):
                        self._generate_alert("gateway_subnet_mismatch", {
                            "server_ip": offer_info.get("server_ip"),
                            "server_mac": offer_info.get("server_mac"),
                            "gateway": gw_str,
                            "offered_ip": offered_ip,
                            "severity": "medium",
                            "description": f"DHCP gateway {gw_str} not in same subnet as offered IP {offered_ip}"
                        })

            offered_ip = offer_info.get("offered_ip", "")
            if (offered_ip.startswith("192.168.") or
                offered_ip.startswith("10.") or
                offered_ip.startswith("172.")):
                server_ip = offer_info.get("server_ip", "")
                if not (server_ip.startswith("192.168.") or
                        server_ip.startswith("10.") or
                        server_ip.startswith("172.")):
                    self._generate_alert("suspicious_ip_range", {
                        "server_ip": server_ip,
                        "offered_ip": offered_ip,
                        "severity": "medium",
                        "description": "External server offering private IP range"
                    })
        except Exception as e:
            self.logger.error(f"Error detecting suspicious config: {e}")

    @staticmethod
    def _same_subnet(ip1: str, ip2: str) -> bool:
        """Best-effort check whether two IPv4 addresses are in the same /24 subnet."""
        try:
            from ipaddress import ip_address
            a = int(ip_address(ip1))
            b = int(ip_address(ip2))
            return (a >> 8) == (b >> 8)
        except Exception:
            return True

    # ------------------------------------------------------------------
    # Alert routing
    # ------------------------------------------------------------------
    def _generate_alert(self, alert_type: str, details: Dict):
        try:
            source_ip = details.get("server_ip") or details.get("source_ip")
            target_ip = details.get("target_ip")
            severity = details.get("severity", "medium")
            description = details.get("description")

            if self._alert_callback is not None:
                self._alert_callback(
                    detector="dhcp_spoofing",
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
                    "detector": "dhcp_spoofing",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"DHCP Spoofing Alert: {alert}")

            if getattr(self, "_network_monitor", None) is not None and source_ip:
                try:
                    self._network_monitor.record_suspicious(source_ip, alert_type)
                except Exception:
                    pass

            return details
        except Exception as e:
            self.logger.error(f"Error generating DHCP alert: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting DHCP spoofing detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        self.is_running = False
        self.logger.info("Stopping DHCP spoofing detector")

    def status(self) -> str:
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        return {
            "detector": "dhcp_spoofing",
            "status": self.status(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "uptime_seconds": int((datetime.utcnow() - self._started_at).total_seconds())
            if self._started_at else 0,
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "last_error": self._last_error,
            "thread_alive": bool(self.monitor_thread and self.monitor_thread.is_alive()),
            "dhcp_servers_known": len(self.dhcp_servers),
        }

    def get_thread(self) -> Optional[threading.Thread]:
        return self.monitor_thread

    def statistics(self) -> dict:
        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "dhcp_servers_known": len(self.dhcp_servers),
        }

    def start_monitoring(self):
        self.start()

    def stop_monitoring(self):
        self.stop()
