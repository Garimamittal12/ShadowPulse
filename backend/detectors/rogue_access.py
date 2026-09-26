import scapy.all as scapy
import threading
import logging
import hashlib
import json
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional

try:
    from core.alert_manager import AlertManager
except ImportError:
    AlertManager = None


class RogueAccessDetector:
    """Rogue Access Point Detector.

    Detection logic is preserved exactly as-is. The detector no longer starts
    its own packet capture; it receives packets via ``handle_packet()``.
    """

    def __init__(self, interface: str = None, authorized_aps: List[Dict] = None,
                 monitor_mode: bool = False):
        self.interface = interface
        self.monitor_mode = monitor_mode
        self.authorized_aps = {}
        if authorized_aps:
            for ap in authorized_aps:
                self.authorized_aps[ap.get('bssid', '').lower()] = ap
        else:
            self._load_authorized_aps_from_file()

        self.detected_aps = {}
        self.suspicious_aps = set()
        self.beacon_frames = defaultdict(list)
        self.deauth_events = defaultdict(list)
        self.last_deauth_alert = {}
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
        self.detect_rogue_access(packet)

    # ------------------------------------------------------------------
    # Detection logic (preserved unchanged)
    # ------------------------------------------------------------------
    def detect_rogue_access(self, packet):
        try:
            if packet.haslayer(scapy.Dot11):
                self._analyze_802_11_frame(packet)
            else:
                # Windows fallback: 802.11 monitor-mode frames are not
                # available on standard Npcap/WinPcap adapters. Detect rogue
                # access points via L2/L3 heuristics instead.
                self._analyze_l2_fallback(packet)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in rogue access detection: {e}")

    def _analyze_l2_fallback(self, packet):
        """Windows fallback: detect rogue APs without 802.11 monitor mode.

        When Dot11 frames are unavailable (standard Windows adapter), we
        infer rogue AP activity from:
          1. ARP gateway spoofing - a host answering for the default gateway
             is likely a rogue AP / evil twin impersonating the gateway.
          2. DHCP offers from unknown servers - a rogue AP often runs its own
             DHCP server to hand out malicious config.
          3. Multiple gateway MACs for the same gateway IP (ARP poisoning).
        """
        try:
            # 1. ARP-based gateway spoofing detection.
            if packet.haslayer(scapy.ARP):
                arp = packet[scapy.ARP]
                if arp.op == 2:  # ARP reply
                    src_ip = arp.psrc
                    src_mac = arp.hwsrc
                    if src_ip and src_mac:
                        # Track which MAC claims to own the gateway IP.
                        if not hasattr(self, "_gateway_ip"):
                            self._gateway_ip = None
                            try:
                                from utils.network_scanner import NetworkScanner
                                self._gateway_ip = NetworkScanner.get_gateway()
                            except Exception:
                                pass
                        if self._gateway_ip and src_ip == self._gateway_ip:
                            if not hasattr(self, "_gateway_macs"):
                                self._gateway_macs = {}
                                self._last_gw_alert = {}
                            if src_mac not in self._gateway_macs:
                                self._gateway_macs[src_mac] = datetime.now()
                                # Only alert if we already knew a different gateway MAC.
                                if len(self._gateway_macs) > 1:
                                    now = datetime.now()
                                    last = self._last_gw_alert.get(src_ip)
                                    if last is None or (now - last).total_seconds() > 60:
                                        self._last_gw_alert[src_ip] = now
                                        self._generate_alert("gateway_mac_spoofing", {
                                            "gateway_ip": src_ip,
                                            "gateway_mac": src_mac,
                                            "known_macs": list(self._gateway_macs.keys()),
                                            "severity": "high",
                                            "description": f"Multiple MACs claiming gateway IP {src_ip} - possible rogue AP/ARP spoof"
                                        })
                                    self.suspicious_aps.add(src_mac)

            # 2. DHCP-based rogue AP detection.
            # Only alert when the DHCP server has a PUBLIC (non-RFC1918) IP.
            # A private-IP DHCP server that differs from the gateway is completely
            # normal in enterprise/ISP networks and home routers. Only a public-IP
            # DHCP server or one with no IP at all is genuinely suspicious.
            if packet.haslayer(scapy.DHCP):
                try:
                    dhcp = packet[scapy.DHCP]
                    options = {}
                    for opt in dhcp.options:
                        if isinstance(opt, tuple) and len(opt) == 2:
                            options[opt[0]] = opt[1]
                    msg_type = options.get("message-type")
                    if msg_type in (2, 5):  # OFFER / ACK
                        server_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else None
                        server_mac = packet[scapy.Ether].src if packet.haslayer(scapy.Ether) else None
                        if server_ip and server_mac:
                            if not hasattr(self, "_dhcp_servers"):
                                self._dhcp_servers = {}
                            if server_mac not in self._dhcp_servers:
                                self._dhcp_servers[server_mac] = server_ip
                                # Only alert if the DHCP server is a PUBLIC IP.
                                # Private-IP DHCP servers (192.168.x.x, 10.x.x.x, 172.16-31.x.x)
                                # that differ from the gateway are NORMAL on enterprise networks
                                # and must NOT generate false positive alerts.
                                _is_private = (
                                    server_ip.startswith('192.168.') or
                                    server_ip.startswith('10.') or
                                    server_ip.startswith('169.254.') or
                                    server_ip.startswith('172.') and any(
                                        server_ip.startswith(f'172.{i}.') for i in range(16, 32)
                                    )
                                )
                                if not _is_private:
                                    self._generate_alert("rogue_dhcp_server", {
                                        "server_ip": server_ip,
                                        "server_mac": server_mac,
                                        "gateway_ip": self._gateway_ip,
                                        "severity": "high",
                                        "description": f"DHCP server {server_ip} has a PUBLIC IP - likely rogue AP"
                                    })
                                    self.suspicious_aps.add(server_mac)
                except Exception:
                    pass

        except Exception as e:
            self.logger.error(f"Error in L2 fallback analysis: {e}")

    def _load_authorized_aps_from_file(self):
        try:
            config_path = Path(__file__).resolve().parents[1] / 'authorized_aps.json'
            if config_path.exists():
                with config_path.open('r', encoding='utf-8') as f:
                    authorized_list = json.load(f)
                for ap in authorized_list:
                    self.authorized_aps[ap.get('bssid', '').lower()] = ap
        except Exception as e:
            self.logger.debug(f"Failed to load authorized APs from file: {e}")

    def _analyze_802_11_frame(self, packet):
        try:
            dot11_layer = packet[scapy.Dot11]

            frame_type = packet.type
            frame_subtype = packet.subtype

            if frame_type == 0:
                if frame_subtype == 8:
                    self._analyze_beacon_frame(packet)
                elif frame_subtype == 5:
                    self._analyze_probe_response(packet)
                elif frame_subtype == 4:
                    self._analyze_probe_request(packet)
                elif frame_subtype == 12:
                    self._analyze_deauth_frame(packet)
                elif frame_subtype in [0, 2]:
                    self._analyze_association_frame(packet)

            elif frame_type == 2:
                self._analyze_data_frame(packet)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing 802.11 frame: {e}")

    def _analyze_beacon_frame(self, packet):
        try:
            dot11_layer = packet[scapy.Dot11]
            bssid = dot11_layer.addr3.lower() if dot11_layer.addr3 else "unknown"

            if packet.haslayer(scapy.Dot11Beacon):
                beacon = packet[scapy.Dot11Beacon]

                ap_info = {
                    "bssid": bssid,
                    "timestamp": datetime.now(),
                    "beacon_interval": beacon.beacon_interval,
                    "capabilities": beacon.cap,
                    "channel": self._get_channel_from_packet(packet),
                    "rssi": self._get_signal_strength(packet),
                    "ssid": None,
                    "encryption": None,
                    "vendor": self._get_vendor_from_mac(bssid)
                }

                if packet.haslayer(scapy.Dot11Elt):
                    self._parse_information_elements(packet, ap_info)

                self.beacon_frames[bssid].append(ap_info)

                cutoff_time = datetime.now() - timedelta(minutes=5)
                self.beacon_frames[bssid] = [
                    beacon for beacon in self.beacon_frames[bssid]
                    if beacon["timestamp"] > cutoff_time
                ]

                self.detected_aps[bssid] = ap_info

                self._check_rogue_indicators(ap_info)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing beacon frame: {e}")

    def _analyze_probe_response(self, packet):
        try:
            dot11_layer = packet[scapy.Dot11]
            bssid = dot11_layer.addr3.lower() if dot11_layer.addr3 else "unknown"

            if bssid not in self.detected_aps:
                ap_info = {
                    "bssid": bssid,
                    "timestamp": datetime.now(),
                    "detected_via": "probe_response",
                    "channel": self._get_channel_from_packet(packet),
                    "rssi": self._get_signal_strength(packet),
                    "vendor": self._get_vendor_from_mac(bssid)
                }

                if packet.haslayer(scapy.Dot11Elt):
                    self._parse_information_elements(packet, ap_info)

                self.detected_aps[bssid] = ap_info
                self._check_rogue_indicators(ap_info)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing probe response: {e}")

    def _analyze_probe_request(self, packet):
        try:
            dot11_layer = packet[scapy.Dot11]
            client_mac = dot11_layer.addr2.lower() if dot11_layer.addr2 else "unknown"

            if not hasattr(self, 'probe_requests'):
                self.probe_requests = defaultdict(list)

            ssid = ""
            if packet.haslayer(scapy.Dot11Elt):
                elt = packet[scapy.Dot11Elt]
                while isinstance(elt, scapy.Dot11Elt):
                    if elt.ID == 0:
                        ssid = elt.info.decode('utf-8', errors='ignore')
                        break
                    elt = elt.payload

            probe_info = {
                "timestamp": datetime.now(),
                "client_mac": client_mac,
                "ssid": ssid
            }

            self.probe_requests[client_mac].append(probe_info)

            cutoff_time = datetime.now() - timedelta(minutes=2)
            self.probe_requests[client_mac] = [
                probe for probe in self.probe_requests[client_mac]
                if probe["timestamp"] > cutoff_time
            ]

        except Exception as e:
            self.logger.error(f"Error analyzing probe request: {e}")

    def _analyze_association_frame(self, packet):
        try:
            dot11_layer = packet[scapy.Dot11]
            client_mac = dot11_layer.addr2.lower() if dot11_layer.addr2 else "unknown"
            ap_mac = dot11_layer.addr1.lower() if dot11_layer.addr1 else "unknown"

            if ap_mac in self.suspicious_aps:
                self._generate_alert("client_connected_to_rogue_ap", {
                    "client_mac": client_mac,
                    "rogue_ap_mac": ap_mac,
                    "ap_info": self.detected_aps.get(ap_mac, {}),
                    "severity": "high",
                    "description": f"Client {client_mac} connected to suspected rogue AP {ap_mac}"
                })

        except Exception as e:
            self.logger.error(f"Error analyzing association frame: {e}")

    def _analyze_deauth_frame(self, packet):
        try:
            dot11_layer = packet[scapy.Dot11]
            src_mac = dot11_layer.addr2.lower() if dot11_layer.addr2 else "unknown"
            dst_mac = dot11_layer.addr1.lower() if dot11_layer.addr1 else "unknown"
            now = datetime.now()
            cutoff = now - timedelta(seconds=30)

            for mac in (src_mac, dst_mac):
                self.deauth_events[mac] = [t for t in self.deauth_events[mac] if t > cutoff]
                self.deauth_events[mac].append(now)

                if len(self.deauth_events[mac]) > 20:
                    last_alert = self.last_deauth_alert.get(mac)
                    if last_alert is None or (now - last_alert).total_seconds() > 60:
                        self.last_deauth_alert[mac] = now
                        self._generate_alert("deauthentication_flood", {
                            "mac": mac,
                            "event_count": len(self.deauth_events[mac]),
                            "time_window_seconds": 30,
                            "severity": "high",
                            "description": f"High deauthentication activity detected for {mac}"
                        })

        except Exception as e:
            self.logger.error(f"Error analyzing deauth frame: {e}")

    def _analyze_data_frame(self, packet):
        try:
            pass
        except Exception as e:
            self.logger.error(f"Error analyzing data frame: {e}")

    def _parse_information_elements(self, packet, ap_info: Dict):
        try:
            elt = packet[scapy.Dot11Elt]

            while isinstance(elt, scapy.Dot11Elt):
                if elt.ID == 0:
                    ap_info["ssid"] = elt.info.decode('utf-8', errors='ignore')
                elif elt.ID == 3:
                    if len(elt.info) >= 1:
                        ap_info["channel"] = elt.info[0]
                elif elt.ID == 48:
                    ap_info["encryption"] = "WPA2"
                elif elt.ID == 221:
                    if len(elt.info) >= 4 and elt.info[:4] == b'\x00\x50\xf2\x01':
                        ap_info["encryption"] = "WPA"

                elt = elt.payload
                if not isinstance(elt, scapy.Dot11Elt):
                    break

        except Exception as e:
            self.logger.error(f"Error parsing information elements: {e}")

    def _check_rogue_indicators(self, ap_info: Dict):
        try:
            bssid = ap_info["bssid"]

            if self.authorized_aps and bssid not in self.authorized_aps:
                ssid = ap_info.get("ssid", "")
                for auth_bssid, auth_ap in self.authorized_aps.items():
                    if auth_ap.get("ssid") == ssid and auth_bssid != bssid:
                        self.suspicious_aps.add(bssid)
                        self._generate_alert("ssid_impersonation", {
                            "rogue_bssid": bssid,
                            "legitimate_bssid": auth_bssid,
                            "ssid": ssid,
                            "ap_info": ap_info,
                            "severity": "critical",
                            "description": f"Rogue AP impersonating SSID '{ssid}'"
                        })
                        return

                self._generate_alert("unauthorized_access_point", {
                    "bssid": bssid,
                    "ssid": ssid,
                    "ap_info": ap_info,
                    "severity": "medium",
                    "description": f"Unauthorized access point detected: {ssid} ({bssid})"
                })

            self._check_suspicious_characteristics(ap_info)
            self._check_evil_twin_patterns(ap_info)

        except Exception as e:
            self.logger.error(f"Error checking rogue indicators: {e}")

    def _check_suspicious_characteristics(self, ap_info: Dict):
        try:
            bssid = ap_info["bssid"]

            if not ap_info.get("ssid") or ap_info.get("ssid") == "":
                self._generate_alert("hidden_ssid_detected", {
                    "bssid": bssid,
                    "ap_info": ap_info,
                    "severity": "low",
                    "description": f"Hidden SSID detected from {bssid}"
                })

            if ap_info.get("encryption") is None:
                capabilities = ap_info.get("capabilities", 0)
                if not (capabilities & 0x0010):
                    self._generate_alert("open_network_detected", {
                        "bssid": bssid,
                        "ssid": ap_info.get("ssid", ""),
                        "ap_info": ap_info,
                        "severity": "medium",
                        "description": f"Open network detected: {ap_info.get('ssid', 'Hidden')} ({bssid})"
                    })

            if self._is_randomized_mac(bssid):
                self._generate_alert("randomized_mac_detected", {
                    "bssid": bssid,
                    "ap_info": ap_info,
                    "severity": "medium",
                    "description": f"AP with randomized MAC detected: {bssid}"
                })

            if len(self.beacon_frames[bssid]) > 5:
                intervals = [beacon.get("beacon_interval", 100) for beacon in self.beacon_frames[bssid]]
                if len(set(intervals)) > 2:
                    self._generate_alert("beacon_interval_variation", {
                        "bssid": bssid,
                        "intervals": list(set(intervals)),
                        "ap_info": ap_info,
                        "severity": "low",
                        "description": f"Suspicious beacon interval variations from {bssid}"
                    })

        except Exception as e:
            self.logger.error(f"Error checking suspicious characteristics: {e}")

    def _check_evil_twin_patterns(self, ap_info: Dict):
        try:
            bssid = ap_info["bssid"]
            ssid = ap_info.get("ssid", "")
            channel = ap_info.get("channel")

            for other_bssid, other_ap in self.detected_aps.items():
                if other_bssid != bssid and other_ap.get("ssid") == ssid:

                    rssi_diff = abs(ap_info.get("rssi", 0) - other_ap.get("rssi", 0))

                    other_channel = other_ap.get("channel")
                    channel_diff = abs(channel - other_channel) if channel and other_channel else 0

                    vendor1 = ap_info.get("vendor", "")
                    vendor2 = other_ap.get("vendor", "")
                    different_vendors = vendor1 != vendor2 and vendor1 and vendor2

                    suspicion_score = 0
                    if rssi_diff > 20:
                        suspicion_score += 2
                    if channel_diff > 0:
                        suspicion_score += 1
                    if different_vendors:
                        suspicion_score += 3

                    if suspicion_score >= 4:
                        self.suspicious_aps.add(bssid)
                        self.suspicious_aps.add(other_bssid)

                        self._generate_alert("evil_twin_detected", {
                            "ap1_bssid": bssid,
                            "ap2_bssid": other_bssid,
                            "ssid": ssid,
                            "suspicion_score": suspicion_score,
                            "rssi_diff": rssi_diff,
                            "channel_diff": channel_diff,
                            "different_vendors": different_vendors,
                            "ap1_info": ap_info,
                            "ap2_info": other_ap,
                            "severity": "critical",
                            "description": f"Potential evil twin attack detected for SSID '{ssid}'"
                        })

        except Exception as e:
            self.logger.error(f"Error checking evil twin patterns: {e}")

    def _get_channel_from_packet(self, packet) -> Optional[int]:
        try:
            if packet.haslayer(scapy.Dot11Elt):
                elt = packet[scapy.Dot11Elt]
                while isinstance(elt, scapy.Dot11Elt):
                    if elt.ID == 3 and len(elt.info) >= 1:
                        return int(elt.info[0])
                    if not hasattr(elt, "payload"):
                        break
                    elt = elt.payload
        except Exception as e:
            self.logger.debug(f"Channel extraction failed: {e}")
        return None

    def _get_signal_strength(self, packet) -> int:
        try:
            if packet.haslayer(scapy.RadioTap):
                radiotap = packet[scapy.RadioTap]
                if hasattr(radiotap, "dBm_AntSignal"):
                    return int(radiotap.dBm_AntSignal)
                if hasattr(radiotap, "notdecoded"):
                    if len(radiotap.notdecoded) >= 4:
                        return -(256 - radiotap.notdecoded[-4])
            return -100
        except Exception as e:
            self.logger.debug(f"RSSI extraction failed: {e}")
            return -100

    def _get_vendor_from_mac(self, mac_address: str) -> str:
        try:
            oui = mac_address.replace(':', '').upper()[:6]

            oui_mapping = {
                '000C29': 'VMware',
                '001B63': 'Apple',
                '00E04C': 'Realtek',
                '001E2A': 'The Linksys Group',
                '00226B': 'Netgear',
                '001F3F': 'Netgear',
                '002454': 'Netgear',
                '0016B6': 'Cisco',
                '00A0C9': 'Intel'
            }

            return oui_mapping.get(oui, 'Unknown')
        except Exception:
            return 'Unknown'

    def _is_randomized_mac(self, mac_address: str) -> bool:
        try:
            first_octet = int(mac_address.split(':')[0], 16)
            return bool(first_octet & 0x02)
        except Exception:
            return False

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
                    detector="rogue_access",
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
                    "detector": "rogue_access",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"Rogue Access Alert: {alert}")

            return details
        except Exception as e:
            self.logger.error(f"Error generating Rogue Access alert: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting rogue access detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        self.is_running = False
        self.logger.info("Stopping rogue access detector")

    def status(self) -> str:
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        return {
            "detector": "rogue_access",
            "status": self.status(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "uptime_seconds": int((datetime.utcnow() - self._started_at).total_seconds())
            if self._started_at else 0,
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "last_error": self._last_error,
            "thread_alive": bool(self.monitor_thread and self.monitor_thread.is_alive()),
            "detected_aps": len(self.detected_aps),
            "suspicious_aps": len(self.suspicious_aps),
            "capability": "active" if self.monitor_mode else "limited",
            "limitation": None if self.monitor_mode else (
                "802.11 monitor mode is unavailable; only ARP/DHCP fallback indicators are active"
            ),
        }

    def get_thread(self) -> Optional[threading.Thread]:
        return self.monitor_thread

    def statistics(self) -> dict:
        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "detected_aps": len(self.detected_aps),
            "suspicious_aps": list(self.suspicious_aps),
        }

    def nearby_aps(self) -> List[dict]:
        """Return current nearby access points for /api/rogue."""
        result = []
        for bssid, info in self.detected_aps.items():
            result.append({
                "bssid": bssid,
                "ssid": info.get("ssid", ""),
                "channel": info.get("channel"),
                "rssi": info.get("rssi"),
                "encryption": info.get("encryption"),
                "vendor": info.get("vendor"),
                "authorized": bssid in self.authorized_aps,
                "suspicious": bssid in self.suspicious_aps,
                "flags": self._flags_for_ap(bssid, info),
            })
        return result

    def authorized_list(self) -> List[dict]:
        return list(self.authorized_aps.values())

    def _flags_for_ap(self, bssid: str, info: dict) -> List[str]:
        flags = []
        if bssid in self.suspicious_aps:
            flags.append("Suspicious")
        if not info.get("ssid"):
            flags.append("Hidden SSID")
        if info.get("encryption") is None:
            flags.append("Open Network")
        if self._is_randomized_mac(bssid):
            flags.append("Randomized MAC")
        if any(other.get("ssid") == info.get("ssid") and other_bssid != bssid
               for other_bssid, other in self.detected_aps.items()):
            flags.append("Evil Twin")
        return flags

    def start_monitoring(self):
        self.start()

    def stop_monitoring(self):
        self.stop()
