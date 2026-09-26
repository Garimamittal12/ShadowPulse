"""
NetworkMonitor
==============
Live network device discovery and tracking.

Two complementary discovery mechanisms:

1. **Active ARP scan** — periodically sends ARP requests across the configured
   network range and records responding IP/MAC pairs. This is the primary
   discovery mechanism for offline devices.

2. **Passive learning** — inspects every captured packet (via the dispatcher)
   and learns source/destination IP + MAC pairs from real traffic. This keeps
   ``last_seen`` fresh even between active scans.

Device records are upserted into the SQLite ``devices`` table. Vendor is
resolved from the MAC OUI when possible; otherwise it is left as "Unknown".

Risk score is computed from security context: a device that appears as the
source of suspicious activity receives a higher risk score (capped at 100).
"""

from __future__ import annotations

import re
import threading
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Set, Tuple

from utils.logger import get_logger
from utils.database import get_db_manager
from utils.network_scanner import NetworkScanner

logger = get_logger()

# ---------------------------------------------------------------------------
# MAC OUI -> vendor lookup (small built-in table + file fallback hook).
# ---------------------------------------------------------------------------
_OUI_VENDORS: Dict[str, str] = {
    "000C29": "VMware",
    "001B63": "Apple",
    "00E04C": "Realtek",
    "001E2A": "Cisco-Linksys",
    "00226B": "Netgear",
    "001F3F": "Netgear",
    "002454": "Netgear",
    "0016B6": "Cisco",
    "00A0C9": "Intel",
    "3C:22:FB": "Dell",
    "B8:27:EB": "Raspberry Pi",
    "DC:A6:32": "Raspberry Pi",
    "E4:5F:01": "Raspberry Pi",
    "00:1A:2B": "TP-Link",
    "AA:BB:CC": "Unknown",
}


def vendor_from_mac(mac: Optional[str]) -> str:
    """Best-effort vendor resolution from MAC OUI."""
    if not mac:
        return "Unknown"
    oui = mac.replace(":", "").replace("-", "").upper()[:6]
    # Try exact 6-hex OUI.
    for prefix, vendor in _OUI_VENDORS.items():
        if prefix.replace(":", "").upper() == oui:
            return vendor
    # Fall back to first 3 bytes for known OUIs.
    first3 = ":".join(mac.split(":")[:3]).upper()
    for prefix, vendor in _OUI_VENDORS.items():
        if prefix.upper() == first3:
            return vendor
    return "Unknown"


def is_randomized_mac(mac: Optional[str]) -> bool:
    """Detect locally-administered (randomized) MACs."""
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except (ValueError, IndexError):
        return False


class NetworkMonitor:
    """Tracks network devices via ARP scans and passive packet learning."""

    def __init__(self, network_range: str = "192.168.1.0/24", scan_interval: int = 30,
                 device_callback=None):
        self.network_range = network_range
        self.scan_interval = scan_interval
        self._db = get_db_manager()
        # record_suspicious() may create a first-seen device while already
        # holding this lock, so it must be re-entrant.
        self._lock = threading.RLock()
        # Optional callback invoked when a brand-new device is first discovered.
        self._device_callback = device_callback

        self._gateway = NetworkScanner.get_default_gateway()
        self._local_ip = NetworkScanner.get_local_ip()
        # Track gateway MAC address when available (best-effort)
        self._gateway_mac: Optional[str] = NetworkScanner.get_mac_for_ip(self._gateway) if self._gateway else None
        self._known_hosts: Dict[str, dict] = {}  # ip -> device dict

        # Track risk contributors: ip -> set of reasons
        self._risk_reasons: Dict[str, Set[str]] = {}
        self._last_scan_at: Optional[datetime] = None
        self._scan_count = 0

        # Packet counters per device (ip -> packet count observed)
        self._packet_counts: Dict[str, int] = {}
        # One summarized event per flow/protocol/minute; raw packets and
        # payloads are deliberately never stored in SQLite.
        self._last_summary_at: Dict[Tuple[str, str, str], datetime] = {}
        # Online/offline tracking (ip -> last_seen handled by _known_hosts)
        self._offline_timeout = 300  # seconds without traffic/scan => offline

        # Load existing devices from DB on startup (do not discard).
        self._load_existing()

    # ------------------------------------------------------------------
    # Subnet helper — only track IPs that belong to our local network.
    # ------------------------------------------------------------------
    def _is_local_ip(self, ip: str) -> bool:
        """Return True if ip falls within the monitored network_range.

        This prevents the device tracker from recording every internet IP
        seen in captured packets (e.g. Google, Azure, Akamai CDN addresses)
        as a "device". Only IPs on the local LAN subnet are relevant.
        """
        if not ip:
            return False
        # Fast-path: reject obvious non-addresses.
        if ip in ('0.0.0.0', '255.255.255.255'):
            return False
        # Reject multicast range (224.0.0.0/4).
        try:
            first_octet = int(ip.split('.')[0])
            if first_octet >= 224:
                return False
            if first_octet == 127:  # loopback
                return False
        except (ValueError, IndexError):
            return False
        try:
            from ipaddress import ip_address, ip_network
            address = ip_address(ip)
            network = ip_network(self.network_range, strict=False)
            return address in network and address not in (network.network_address, network.broadcast_address)
        except Exception:
            # If the network range is unparseable, fall back to accepting
            # all private addresses so we don't lose all device tracking.
            return (
                ip.startswith('192.168.') or
                ip.startswith('10.') or
                ip.startswith('172.')
            )

    # ------------------------------------------------------------------
    # Packet learning (passive)
    # ------------------------------------------------------------------
    def handle_packet(self, packet) -> None:
        """Passively learn devices from captured traffic."""
        try:
            src_ip, dst_ip, src_mac, dst_mac = self._extract_addrs(packet)
        except Exception:
            return

        # Only track IPs that are on the local subnet — not internet addresses.
        if src_ip and src_ip != "0.0.0.0" and self._is_local_ip(src_ip):
            self._learn_device(src_ip, src_mac)
            self._count_packet(src_ip)
        if (dst_ip and
                dst_ip != "255.255.255.255" and
                not dst_ip.startswith("224.") and
                self._is_local_ip(dst_ip)):
            self._learn_device(dst_ip, dst_mac)
            self._count_packet(dst_ip)
        if src_ip and dst_ip:
            self._record_network_summary(packet, src_ip, dst_ip)

    def _record_network_summary(self, packet, src_ip: str, dst_ip: str) -> None:
        """Persist low-volume network activity summaries for dashboard metrics."""
        try:
            protocol = "ARP" if packet.haslayer("ARP") else "IP"
            source_port = dest_port = None
            if packet.haslayer("TCP"):
                protocol = "TCP"
                source_port, dest_port = packet["TCP"].sport, packet["TCP"].dport
            elif packet.haslayer("UDP"):
                protocol = "UDP"
                source_port, dest_port = packet["UDP"].sport, packet["UDP"].dport
            elif packet.haslayer("ICMP"):
                protocol = "ICMP"
            key = (src_ip, dst_ip, protocol)
            now = datetime.utcnow()
            with self._lock:
                last = self._last_summary_at.get(key)
                if last and (now - last).total_seconds() < 60:
                    return
                self._last_summary_at[key] = now
            self._db.insert_network_log(
                src_ip, dst_ip, protocol, source_port=source_port,
                dest_port=dest_port, packet_size=len(packet)
            )
        except Exception as exc:
            logger.debug(f"NetworkMonitor: summary logging error: {exc}")

    def _count_packet(self, ip: str) -> None:
        with self._lock:
            self._packet_counts[ip] = self._packet_counts.get(ip, 0) + 1

    def _extract_addrs(self, packet) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str]]:
        src_ip = dst_ip = None
        src_mac = dst_mac = None
        try:
            if packet.haslayer("IP"):
                src_ip = packet["IP"].src
                dst_ip = packet["IP"].dst
            elif packet.haslayer("ARP"):
                src_ip = packet["ARP"].psrc
                dst_ip = packet["ARP"].pdst
            if packet.haslayer("Ether"):
                src_mac = packet["Ether"].src
                dst_mac = packet["Ether"].dst
        except Exception:
            pass
        return src_ip, dst_ip, src_mac, dst_mac

    def _learn_device(self, ip: str, mac: Optional[str]) -> None:
        # A broadcast/multicast MAC is an Ethernet delivery address, not a
        # device identity.  Never let it create or overwrite a device record.
        if mac and not NetworkScanner._is_valid_arp_device(ip, mac, self.network_range):
            return
        with self._lock:
            now = datetime.utcnow()
            existing = self._known_hosts.get(ip)
            # Update gateway MAC if this ip is the configured gateway.
            # IMPORTANT: Never record ff:ff:ff:ff:ff:ff (broadcast) as the
            # gateway MAC — ARP broadcast replies are not the gateway itself.
            if ip == self._gateway and mac and mac.lower() != 'ff:ff:ff:ff:ff:ff':
                prev = getattr(self, '_gateway_mac', None)
                if mac != prev:
                    logger.info(f"NetworkMonitor: gateway MAC changed {prev} -> {mac}")
                    self._gateway_mac = mac
            if existing is None:
                self._known_hosts[ip] = {
                    "ip_address": ip,
                    "mac_address": mac,
                    "hostname": None,
                    "vendor": vendor_from_mac(mac),
                    "device_type": self._guess_device_type(ip, mac),
                    "first_seen": now,
                    "last_seen": now,
                    "_last_db_sync": now,
                    "is_trusted": False,
                    "is_rogue": False,
                    "risk_score": 0,
                }
                self._db.upsert_device(
                    ip,
                    mac_address=mac,
                    hostname=None,
                    vendor=self._known_hosts[ip]["vendor"],
                    device_type=self._known_hosts[ip]["device_type"],
                )
                self._notify_new_device(self._known_hosts[ip])
                if mac:
                    self._resolve_hostname_async(ip)
            else:
                updated_attr = False
                if mac and existing.get("mac_address") != mac:
                    existing["mac_address"] = mac
                    updated_attr = True
                existing["last_seen"] = now
                if mac and existing.get("vendor", "Unknown") == "Unknown":
                    v = vendor_from_mac(mac)
                    if v != "Unknown":
                        existing["vendor"] = v
                        updated_attr = True
                
                last_db_sync = existing.get("_last_db_sync", datetime.min)
                if updated_attr or (now - last_db_sync).total_seconds() > 30:
                    existing["_last_db_sync"] = now
                    self._db.upsert_device(
                        ip,
                        mac_address=existing.get("mac_address"),
                        hostname=existing.get("hostname"),
                        vendor=existing.get("vendor"),
                        device_type=existing.get("device_type"),
                    )

    def _resolve_hostname_async(self, ip: str) -> None:
        """Resolve device hostname in a background thread without holding self._lock."""
        def _worker():
            try:
                host = NetworkScanner.get_hostname_by_ip(ip)
                if host:
                    with self._lock:
                        if ip in self._known_hosts:
                            self._known_hosts[ip]["hostname"] = host
                            self._db.upsert_device(ip, hostname=host)
            except Exception:
                pass
        threading.Thread(target=_worker, daemon=True, name=f"hostname-resolve-{ip}").start()

    # ------------------------------------------------------------------
    # Active ARP scan
    # ------------------------------------------------------------------
    def scan(self, network_range: Optional[str] = None) -> int:
        """Run an ARP sweep of the monitored or explicitly supplied range."""
        found = 0
        try:
            scan_range = network_range or self.network_range
            # Do not silently scan an invalid or broad fallback range supplied
            # by an API caller.  The configured monitored range remains the
            # default when no range is requested.
            from ipaddress import ip_network
            ip_network(scan_range, strict=False)
            discovered = NetworkScanner.scan_network(scan_range)
            with self._lock:
                now = datetime.utcnow()
                for ip, mac in discovered:
                    if not NetworkScanner._is_valid_arp_device(ip, mac, scan_range):
                        continue
                    if ip in self._known_hosts:
                        self._known_hosts[ip]["last_seen"] = now
                        if mac:
                            self._known_hosts[ip]["mac_address"] = mac
                    else:
                        self._known_hosts[ip] = {
                            "ip_address": ip,
                            "mac_address": mac,
                            "hostname": None,
                            "vendor": vendor_from_mac(mac),
                            "device_type": self._guess_device_type(ip, mac),
                            "first_seen": now,
                            "last_seen": now,
                            "is_trusted": False,
                            "is_rogue": False,
                            "risk_score": 0,
                        }
                        if mac:
                            self._resolve_hostname_async(ip)
                    self._db.upsert_device(
                        ip,
                        mac_address=mac,
                        hostname=self._known_hosts[ip].get("hostname"),
                        vendor=vendor_from_mac(mac),
                        device_type=self._guess_device_type(ip, mac),
                    )
                    found += 1
                    # If this IP is the gateway, keep gateway_mac up-to-date
                    if ip == self._gateway and mac:
                        prev = getattr(self, '_gateway_mac', None)
                        if mac != prev:
                            logger.info(f"NetworkMonitor: gateway MAC discovered {mac}")
                            self._gateway_mac = mac
            self._scan_count += 1
            self._last_scan_at = now
            logger.info(f"NetworkMonitor: scan found {found} devices")
        except Exception as exc:
            logger.error(f"NetworkMonitor: ARP scan error: {exc}")
        return found

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------
    def record_suspicious(self, ip: Optional[str], reason: str) -> None:
        """Increment risk score for a device involved in suspicious activity."""
        if not ip:
            return
        # Only track risk for devices on the local subnet. DNS/SSL alerts
        # can reference public internet IPs which should not be added as
        # "devices" on the dashboard.
        if not self._is_local_ip(ip):
            return
        with self._lock:
            if ip not in self._known_hosts:
                self._learn_device(ip, None)
            self._risk_reasons.setdefault(ip, set()).add(reason)
            weights = {
                "gateway_mac_change": 25, "arp_spoofing": 20,
                "dns_response_conflict": 15, "unauthorized_dns_server": 15,
                "unauthorized_dhcp_server": 20, "rogue_gateway": 20,
                "unauthorized_icmp_redirect": 15, "rogue_gateway_redirect": 20,
                "https_to_http_downgrade": 25, "ssl_strip_detected": 25,
                "possible_mitm_chain": 35,
            }
            score = min(100, sum(weights.get(item, 10) for item in self._risk_reasons[ip]))
            self._known_hosts[ip]["risk_score"] = score
            self._known_hosts[ip]["risk_reasons"] = sorted(self._risk_reasons[ip])
            self._db.upsert_device(ip, risk_score=score)

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------
    def devices(self, include_inactive: bool = False) -> List[dict]:
        """Return live device list (in-memory state merged with DB)."""
        now = datetime.utcnow()
        with self._lock:
            result = []
            for ip, d in self._known_hosts.items():
                item = dict(d)
                item["ip"] = ip
                item["is_gateway"] = ip == self._gateway
                item["packet_count"] = self._packet_counts.get(ip, 0)
                # Online/offline based on last_seen recency.
                last_seen = item.get("last_seen")
                try:
                    if isinstance(last_seen, str):
                        last_seen = datetime.fromisoformat(last_seen.replace("Z", "+00:00")).replace(tzinfo=None)
                    elif last_seen is None:
                        last_seen = now
                except Exception:
                    last_seen = now
                # Preserve a datetime for sorting, and attach ISO string later for JSON.
                item["_last_seen_dt"] = last_seen
                online = (now - last_seen).total_seconds() < self._offline_timeout
                item["online"] = online
                if not include_inactive and not online:
                    continue
                item["suspicious"] = item.get("risk_score", 0) > 5 or item.get("is_rogue", False)
                result.append(item)
            result.sort(key=lambda x: x.get("_last_seen_dt") or datetime.min, reverse=True)
            # Convert datetime markers to ISO strings for JSON serialization
            for r in result:
                dt = r.get("_last_seen_dt")
                r["last_seen"] = dt.isoformat() + "Z" if dt else None
                r.pop("_last_seen_dt", None)
            return result

    def device_count(self) -> int:
        with self._lock:
            return len(self._known_hosts)

    def online_count(self) -> int:
        return sum(1 for d in self.devices(include_inactive=True) if d.get("online"))

    def rogue_devices(self) -> List[dict]:
        """Return only devices flagged as rogue or high-risk."""
        return [d for d in self.devices(include_inactive=True) if d.get("is_rogue") or d.get("risk_score", 0) > 5]

    def get_gateway(self) -> Optional[str]:
        return self._gateway or NetworkScanner.get_default_gateway()

    def get_gateway_mac(self) -> Optional[str]:
        """Return the best-known gateway MAC address (if any)."""
        return getattr(self, '_gateway_mac', None)

    def set_gateway(self, gw: str) -> None:
        """Update the known gateway (e.g. detected via DHCP)."""
        with self._lock:
            self._gateway = gw

    def status_dict(self) -> dict:
        return {
            "last_scan_at": self._last_scan_at.isoformat() if self._last_scan_at else None,
            "scan_count": self._scan_count,
            "device_count": self.device_count(),
            "online_count": self.online_count(),
            "rogue_count": len(self.rogue_devices()),
            "gateway": self.get_gateway(),
            "gateway_mac": self.get_gateway_mac(),
            "network_range": self.network_range,
            "local_ip": self._local_ip,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------
    def _notify_new_device(self, device: dict) -> None:
        """Invoke the device_discovered callback (best-effort)."""
        if self._device_callback is None:
            return
        try:
            self._device_callback(device)
        except Exception as exc:
            logger.debug(f"NetworkMonitor: device callback error: {exc}")

    def _load_existing(self) -> None:
        """Load devices from DB, but only those within the monitored subnet.

        Historical entries for internet IPs (accumulated before the
        _is_local_ip filter was added) are silently skipped so the
        dashboard device count reflects only actual LAN devices.
        """
        try:
            for row in self._db.get_devices(include_inactive=True):
                ip = row.get("ip_address")
                if not ip:
                    continue
                # Only load devices that belong to the local subnet.
                if not self._is_local_ip(ip):
                    continue
                self._known_hosts[ip] = {
                    "ip_address": ip,
                    "mac_address": row.get("mac_address"),
                    "hostname": row.get("hostname"),
                    "vendor": row.get("vendor"),
                    "device_type": row.get("device_type"),
                    "first_seen": row.get("first_seen"),
                    "last_seen": row.get("last_seen"),
                    "is_trusted": bool(row.get("is_trusted")),
                    "is_rogue": bool(row.get("is_rogue")),
                    "risk_score": row.get("risk_score") or 0,
                }
        except Exception as exc:
            logger.warning(f"NetworkMonitor: failed to load existing devices: {exc}")

    @staticmethod
    def _guess_device_type(ip: str, mac: Optional[str]) -> str:
        if mac and mac.upper().startswith(("B8:27:EB", "DC:A6:32", "E4:5F:01")):
            return "iot"
        return "unknown"

