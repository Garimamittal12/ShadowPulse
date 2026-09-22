import socket
import subprocess
import platform
import re
import psutil
from ipaddress import ip_address, ip_network, ip_interface
from typing import Dict, List, Optional, Tuple

# Adapters that should not be used for LAN MITM monitoring.
_VIRTUAL_IFACE_KEYWORDS = (
    "loopback", "bluetooth", "virtual", "vmware", "vbox", "hyper-v",
    "warp", "vpn", "tun", "tap", "pseudo", "teredo", "isatap", "npcap",
    "hamachi", "tailscale", "zerotier", "wireguard", "vethernet",
)


class NetworkScanner:

    @staticmethod
    def _is_valid_arp_device(ip: str, mac: str, network_range: str) -> bool:
        """Return whether an ARP record identifies a real host on this subnet.

        Some Windows/Npcap combinations feed the outgoing broadcast ARP
        request back into Scapy's receive path.  That request has the target
        IP but the broadcast Ethernet MAC, and must never be recorded as a
        device.
        """
        try:
            address = ip_address(ip)
            network = ip_network(network_range, strict=False)
            if address not in network or address in (network.network_address, network.broadcast_address):
                return False

            parts = mac.replace("-", ":").lower().split(":")
            if len(parts) != 6 or any(len(part) != 2 for part in parts):
                return False
            octets = [int(part, 16) for part in parts]
            # Broadcast, all-zero, and multicast Ethernet addresses do not
            # identify an individual network device.
            if all(value == 0xFF for value in octets) or all(value == 0 for value in octets):
                return False
            return not bool(octets[0] & 0x01)
        except (ValueError, TypeError):
            return False

    @staticmethod
    def get_local_ip():
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return None

    @staticmethod
    def _is_virtual_interface(name: str) -> bool:
        lowered = (name or "").lower()
        if lowered.startswith(("lo", "loopback")):
            return True
        return any(keyword in lowered for keyword in _VIRTUAL_IFACE_KEYWORDS)

    @staticmethod
    def _interface_ipv4(name: str) -> Optional[str]:
        """Return the primary IPv4 address for a psutil interface name."""
        try:
            for snic in psutil.net_if_addrs().get(name, []):
                if snic.family != socket.AF_INET:
                    continue
                ip = snic.address
                if ip.startswith(("127.", "169.254.")):
                    continue
                return ip
        except Exception:
            pass
        return None

    @staticmethod
    def get_best_interface() -> Optional[str]:
        """Pick the best physical LAN adapter (Wi-Fi / Ethernet) that is UP."""
        try:
            stats = psutil.net_if_stats()
            candidates: List[Tuple[int, str, str]] = []

            for name, snics in psutil.net_if_addrs().items():
                if NetworkScanner._is_virtual_interface(name):
                    continue
                if re.search(r"\*\s*\d+$", name):
                    continue

                st = stats.get(name)
                if st is not None and not st.isup:
                    continue

                ip = None
                for snic in snics:
                    if snic.family != socket.AF_INET:
                        continue
                    candidate_ip = snic.address
                    if candidate_ip.startswith(("127.", "169.254.")):
                        continue
                    ip = candidate_ip
                    break
                if not ip:
                    continue

                score = 0
                lowered = name.lower()
                if "wi-fi" in lowered or "wifi" in lowered or "wireless" in lowered:
                    score += 20
                elif "ethernet" in lowered:
                    score += 15
                elif "local area connection" in lowered:
                    score += 10
                candidates.append((score, name, ip))

            if candidates:
                candidates.sort(key=lambda item: item[0], reverse=True)
                return candidates[0][1]
        except Exception:
            pass
        return NetworkScanner.get_active_interface()

    @staticmethod
    def get_active_interface() -> Optional[str]:
        """Return the psutil interface name for the host's primary IPv4 address."""
        local_ip = NetworkScanner.get_local_ip()
        if not local_ip:
            return NetworkScanner.get_best_interface()

        try:
            for name, snics in psutil.net_if_addrs().items():
                for snic in snics:
                    if snic.family == socket.AF_INET and snic.address == local_ip:
                        return name
        except Exception:
            pass

        return NetworkScanner.get_best_interface()

    @staticmethod
    def _scapy_iface_name(iface) -> Optional[str]:
        """Normalize a Scapy interface object or string to a capture device name."""
        if iface is None:
            return None
        if isinstance(iface, str):
            return iface
        for attr in ("name", "network_name", "description"):
            value = getattr(iface, attr, None)
            if value:
                return str(value)
        return str(iface)

    @staticmethod
    def scapy_iface_for_ip(target_ip: str) -> Optional[str]:
        """Map an IPv4 address to the Scapy/Npcap interface name on Windows."""
        if not target_ip:
            return None
        try:
            import scapy.all as scapy

            if hasattr(scapy.conf, "ifaces") and scapy.conf.ifaces:
                for iface in scapy.conf.ifaces.values():
                    ips = getattr(iface, "ips", None) or []
                    if not ips and getattr(iface, "ip", None):
                        ips = [iface.ip]
                    if target_ip in ips:
                        return NetworkScanner._scapy_iface_name(iface)

            working = scapy.get_working_if()
            if working:
                return NetworkScanner._scapy_iface_name(working)
        except Exception:
            pass
        return None

    @staticmethod
    def resolve_capture_interface(config_iface: Optional[str] = None) -> Dict[str, Optional[str]]:
        """Resolve the interface Scapy must sniff on (Windows Npcap GUID aware).

        Returns a dict with:
            scapy_iface  - name passed to AsyncSniffer (Npcap device path on Windows)
            psutil_name  - human-readable adapter name
            local_ip     - IPv4 bound to that adapter
            network_range - CIDR for ARP scans on the active subnet
        """
        config_iface = (config_iface or "").strip()
        auto = not config_iface or config_iface.lower() in ("auto", "default", "any")

        psutil_name = None
        local_ip = None

        if not auto and NetworkScanner.is_valid_interface(config_iface):
            psutil_name = config_iface
            local_ip = NetworkScanner._interface_ipv4(config_iface)
        else:
            if not auto and config_iface:
                # Configured name is invalid on this host (e.g. eth0 on Windows).
                pass
            psutil_name = NetworkScanner.get_best_interface()
            local_ip = NetworkScanner._interface_ipv4(psutil_name) if psutil_name else None

        if not local_ip:
            local_ip = NetworkScanner.get_local_ip()

        scapy_iface = NetworkScanner.scapy_iface_for_ip(local_ip) if local_ip else None
        if not scapy_iface:
            try:
                import scapy.all as scapy
                scapy_iface = NetworkScanner._scapy_iface_name(scapy.get_working_if())
            except Exception:
                scapy_iface = None

        if not scapy_iface:
            try:
                import scapy.all as scapy
                for candidate in scapy.get_if_list():
                    if "loopback" not in candidate.lower():
                        scapy_iface = candidate
                        break
            except Exception:
                pass

        network_range = NetworkScanner.get_network_range(local_ip, psutil_name)
        return {
            "scapy_iface": scapy_iface,
            "psutil_name": psutil_name,
            "local_ip": local_ip,
            "network_range": network_range,
            "configured": config_iface or "auto",
        }

    @staticmethod
    def get_network_range(local_ip: Optional[str] = None, psutil_name: Optional[str] = None) -> str:
        """Derive a /24 (or masked) CIDR for the active adapter."""
        if psutil_name:
            try:
                for snic in psutil.net_if_addrs().get(psutil_name, []):
                    if snic.family != socket.AF_INET:
                        continue
                    ip = snic.address
                    mask = snic.netmask
                    if ip and mask and not ip.startswith(("127.", "169.254.")):
                        network = ip_interface(f"{ip}/{mask}").network
                        return str(network)
            except Exception:
                pass

        local_ip = local_ip or NetworkScanner.get_local_ip()
        if local_ip:
            parts = local_ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
        return "192.168.1.0/24"

    @staticmethod
    def is_valid_interface(iface: Optional[str]) -> bool:
        """Check whether an interface name exists on this machine."""
        if not iface:
            return False
        try:
            return iface.lower() in {i.lower() for i in psutil.net_if_addrs().keys()}
        except Exception:
            return False

    @staticmethod
    def get_hostname():
        try:
            return socket.gethostname()
        except Exception:
            return "Unknown"

    @staticmethod
    def get_default_gateway():

        gateways = psutil.net_if_addrs()

        system = platform.system()

        try:
            if system == "Windows":
                output = subprocess.check_output(
                    "ipconfig",
                    shell=True,
                    text=True
                )

                for line in output.splitlines():
                    match = re.search(
                        r"Default Gateway[\s.:]+(\d{1,3}(?:\.\d{1,3}){3})",
                        line,
                        re.IGNORECASE,
                    )
                    if match:
                        gateway = match.group(1)
                        if gateway not in ("0.0.0.0", "255.255.255.255"):
                            return gateway

            else:
                output = subprocess.check_output(
                    ["ip", "route"],
                    text=True
                )

                for line in output.splitlines():
                    if line.startswith("default"):
                        return line.split()[2]

        except Exception:
            pass

        return None

    @staticmethod
    def get_dns_servers():
        """Return every DNS server configured on the host, including continuations."""
        dns_servers = []

        try:

            if platform.system() == "Windows":

                output = subprocess.check_output(
                    "ipconfig /all",
                    shell=True,
                    text=True
                )

                collecting = False
                for line in output.splitlines():
                    if "DNS Servers" in line:
                        collecting = True
                        dns = line.split(":", 1)[-1].strip()
                    elif collecting and line[:1].isspace():
                        dns = line.strip()
                    else:
                        collecting = False
                        continue
                    try:
                        ip_address(dns)
                        if dns not in dns_servers:
                            dns_servers.append(dns)
                    except ValueError:
                        pass

            else:

                with open("/etc/resolv.conf", "r") as f:
                    for line in f:
                        if line.startswith("nameserver"):
                            dns_servers.append(line.split()[1])

        except Exception:
            pass

        return dns_servers

    @staticmethod
    def get_network_info():

        return {
            "hostname": NetworkScanner.get_hostname(),
            "local_ip": NetworkScanner.get_local_ip(),
            "gateway": NetworkScanner.get_default_gateway(),
            "dns_servers": NetworkScanner.get_dns_servers()
        }

    @staticmethod
    def get_mac_for_ip(ip: str) -> Optional[str]:
        """Resolve a MAC address for the given IPv4 address.

        Tries a scapy ARP request first, falling back to parsing the OS ARP
        cache (`arp -a`) when scapy is unavailable or fails.
        """
        if not ip:
            return None
        try:
            import scapy.all as scapy
            ans, _ = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=ip), timeout=2, verbose=False)
            for _, r in ans:
                mac = getattr(r, 'hwsrc', None) or r.sprintf('%ARP.hwsrc%')
                if mac:
                    return mac.replace('-', ':')
        except Exception:
            pass

        # Fallback: parse `arp -a` output
        try:
            import subprocess
            output = subprocess.check_output(["arp", "-a"], text=True, timeout=3)
            for line in output.splitlines():
                m = re.search(rf"({re.escape(ip)}).*?([0-9a-fA-F:-]{{17}})", line)
                if m:
                    mac = m.group(2).replace('-', ':')
                    return mac
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Active discovery methods (used by NetworkMonitor)
    # ------------------------------------------------------------------
    @staticmethod
    def get_hostname_by_ip(ip: str) -> Optional[str]:
        """Best-effort reverse DNS / NetBIOS hostname resolution."""
        if not ip:
            return None
        try:
            host = socket.gethostbyaddr(ip)
            return host[0] if host and host[0] else None
        except Exception:
            pass
        # NetBIOS lookup on Windows (no external dependency)
        try:
            if platform.system() == "Windows":
                output = subprocess.check_output(
                    ["nbtstat", "-A", ip],
                    shell=True,
                    text=True,
                    timeout=3,
                )
                match = re.search(r"^\s+(\S+)\s+<00>", output, re.MULTILINE)
                if match:
                    return match.group(1)
        except Exception:
            pass
        return None

    @staticmethod
    def scan_network(network_range: str = "192.168.1.0/24", timeout: int = 3) -> List[Tuple[str, Optional[str]]]:
        """Perform an ARP sweep of the given network range.

        Returns a list of (ip, mac) tuples for hosts that responded.
        Uses scapy when available; falls back to ``arp -a`` parsing on
        Windows if scapy cannot send raw packets.
        """
        try:
            import scapy.all as scapy
            ans, _ = scapy.srp(
                scapy.Ether(dst="ff:ff:ff:ff:ff:ff") / scapy.ARP(pdst=network_range),
                timeout=timeout,
                verbose=False,
            )
            results = []
            seen = set()
            for _, rsp in ans:
                mac = getattr(rsp, 'hwsrc', None) or rsp.sprintf('%ARP.hwsrc%')
                ip = getattr(rsp, 'psrc', None) or rsp.sprintf('%ARP.psrc%')
                mac = mac.replace("-", ":") if mac else None
                if ip and mac and NetworkScanner._is_valid_arp_device(ip, mac, network_range) and ip not in seen:
                    results.append((ip, mac))
                    seen.add(ip)
            if results:
                return results
        except Exception:
            pass

        # Fallback: parse `arp -a` output (works on Windows and macOS).
        try:
            output = subprocess.check_output(["arp", "-a"], text=True, timeout=5)
            results = []
            seen = set()
            # Windows: "192.168.1.1    00-1a-2b-3c-4d-5e    dynamic"
            # Linux:   "192.168.1.1  ether 00:1a:2b:3c:4d:5e  C"
            for line in output.splitlines():
                m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F:-]{17})", line)
                if m:
                    ip = m.group(1)
                    mac = m.group(2).replace("-", ":")
                    if NetworkScanner._is_valid_arp_device(ip, mac, network_range) and ip not in seen:
                        results.append((ip, mac))
                        seen.add(ip)
            return results
        except Exception:
            return []

    @staticmethod
    def get_interface_list() -> List[str]:
        """Return available network interface names."""
        try:
            addrs = psutil.net_if_addrs()
            return list(addrs.keys())
        except Exception:
            return []


if __name__ == "__main__":

    info = NetworkScanner.get_network_info()

    print("\n=== ShadowPulse Network Scanner ===")

    for k, v in info.items():
        print(f"{k}: {v}")
