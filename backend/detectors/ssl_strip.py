import scapy.all as scapy
import threading
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional

try:
    from core.alert_manager import AlertManager
except ImportError:
    AlertManager = None


class SSLStripDetector:
    """SSL Strip Attack Detector.

    Detection logic is preserved exactly as-is. The detector no longer starts
    its own packet capture; it receives packets via ``handle_packet()``.
    """

    def __init__(self, interface: str = None):
        self.interface = interface
        self.http_sessions = defaultdict(dict)
        self.https_sessions = defaultdict(dict)
        self.ssl_redirects = defaultdict(list)
        self.suspicious_sessions = set()
        self.dns_spoof_detected = False
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

        # Per-destination cooldown for tls_downgrade_attempt alerts (5 minutes).
        # Prevents the same legitimate server from spamming alerts repeatedly.
        self._tls_downgrade_cooldown: Dict[str, datetime] = {}

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
        self.detect_ssl_strip(packet)

    # ------------------------------------------------------------------
    # Detection logic (preserved unchanged)
    # ------------------------------------------------------------------
    def detect_ssl_strip(self, packet):
        try:
            if packet.haslayer(scapy.TCP):
                tcp_layer = packet[scapy.TCP]
                src_ip = packet[scapy.IP].src
                dst_ip = packet[scapy.IP].dst
                src_port = tcp_layer.sport
                dst_port = tcp_layer.dport

                if dst_port == 80 or src_port == 80:
                    if packet.haslayer(scapy.Raw):
                        payload = packet[scapy.Raw].load.decode('utf-8', errors='replace')
                        self._analyze_http_traffic(payload, src_ip, dst_ip, src_port, dst_port)

                elif dst_port == 443 or src_port == 443:
                    self._analyze_https_traffic(packet, src_ip, dst_ip, src_port, dst_port)

                if packet.haslayer(scapy.Raw):
                    self._analyze_ssl_handshake(packet, src_ip, dst_ip, src_port, dst_port)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in SSL strip detection: {e}")

    def _make_session_key(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        return tuple(sorted([f"{src_ip}:{src_port}", f"{dst_ip}:{dst_port}"]))

    def set_dns_spoof_detected(self, detected: bool = True):
        self.dns_spoof_detected = detected

    def _analyze_http_traffic(self, payload: str, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        try:
            session_key = self._make_session_key(src_ip, dst_ip, src_port, dst_port)

            if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                self._analyze_http_request(payload, session_key, src_ip, dst_ip)
            elif payload.startswith('HTTP/'):
                self._analyze_http_response(payload, session_key, src_ip, dst_ip)

        except Exception as e:
            self.logger.error(f"Error analyzing HTTP traffic: {e}")

    def _analyze_http_request(self, payload: str, session_key: str, src_ip: str, dst_ip: str):
        try:
            lines = payload.split('\r\n')
            request_line = lines[0] if lines else ""

            parts = request_line.split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]

                headers = {}
                for line in lines[1:]:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()

                self._check_ssl_strip_patterns(method, url, headers, session_key, src_ip, dst_ip)

                self.http_sessions[session_key] = {
                    "timestamp": datetime.now(),
                    "method": method,
                    "url": url,
                    "headers": headers,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip
                }

                # --- HTTPS->HTTP downgrade detection ---
                # If this host was previously seen on HTTPS (port 443) and now
                # serves the same content over HTTP (port 80), it's a strong
                # indicator of SSL stripping. Correlate by destination IP.
                host = headers.get('host', '').lower()
                if host:
                    # Check if any HTTPS session exists for this host.
                    for hk, hs in list(self.https_sessions.items()):
                        hs_host = hs.get("host", "").lower()
                        hs_dst = hs.get("dst_ip", "")
                        if (hs_host == host or hs_dst == dst_ip) and hs.get("timestamp"):
                            # Only alert if the HTTPS session was recent (within 5 min).
                            if datetime.now() - hs["timestamp"] < timedelta(minutes=5):
                                self._generate_alert("https_to_http_downgrade", {
                                    "session_key": session_key,
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "host": host,
                                    "url": url,
                                    "method": method,
                                    "severity": "critical",
                                    "description": f"Host {host} previously served HTTPS but now receiving HTTP - possible SSL strip"
                                })
                                break

        except Exception as e:
            self.logger.error(f"Error analyzing HTTP request: {e}")

    def _analyze_http_response(self, payload: str, session_key: str, src_ip: str, dst_ip: str):
        try:
            lines = payload.split('\r\n')
            status_line = lines[0] if lines else ""

            if status_line.startswith('HTTP/'):
                parts = status_line.split()
                if len(parts) >= 2:
                    status_code = parts[1]

                    headers = {}
                    body_start = False
                    body = ""

                    for line in lines[1:]:
                        if not line.strip() and not body_start:
                            body_start = True
                            continue

                        if body_start:
                            body += line + "\n"
                        elif ':' in line:
                            key, value = line.split(':', 1)
                            headers[key.strip().lower()] = value.strip()

                    self._check_redirect_patterns(status_code, headers, body, session_key, src_ip, dst_ip)
                    self._check_ssl_downgrade_patterns(headers, body, session_key, src_ip, dst_ip)

        except Exception as e:
            self.logger.error(f"Error analyzing HTTP response: {e}")

    def _check_ssl_strip_patterns(self, method: str, url: str, headers: Dict, session_key: str, src_ip: str, dst_ip: str):
        try:
            if 'https://' in url:
                self._generate_alert("https_over_http", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "url": url,
                    "method": method,
                    "severity": "high",
                    "description": "HTTPS URL requested over HTTP connection"
                })

            host = headers.get('host', '')
            if self._is_sensitive_site(host):
                if method == 'POST':
                    self._generate_alert("sensitive_post_over_http", {
                        "session_key": session_key,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "host": host,
                        "url": url,
                        "severity": "critical",
                        "description": f"Sensitive POST data to {host} over HTTP"
                    })

            referer = headers.get('referer', '')
            if referer.startswith('https://') and not url.startswith('https://'):
                self._generate_alert("https_to_http_transition", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "referer": referer,
                    "url": url,
                    "severity": "medium",
                    "description": "Transition from HTTPS to HTTP detected"
                })

        except Exception as e:
            self.logger.error(f"Error checking SSL strip patterns: {e}")

    def _check_redirect_patterns(self, status_code: str, headers: Dict, body: str, session_key: str, src_ip: str, dst_ip: str):
        try:
            if status_code in ['301', '302', '303', '307', '308']:
                location = headers.get('location', '')

                if location:
                    if session_key in self.https_sessions:
                        original_session = self.https_sessions[session_key]
                        if location.startswith('http://') and not location.startswith('https://'):
                            self._generate_alert("https_to_http_redirect", {
                                "session_key": session_key,
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "redirect_location": location,
                                "status_code": status_code,
                                "severity": "high",
                                "description": "Redirect from HTTPS to HTTP detected"
                            })

            if 'content-type' in headers and 'text/html' in headers['content-type']:
                self._check_html_modifications(body, session_key, src_ip, dst_ip)

        except Exception as e:
            self.logger.error(f"Error checking redirect patterns: {e}")

    def _check_ssl_downgrade_patterns(self, headers: Dict, body: str, session_key: str, src_ip: str, dst_ip: str):
        """
        Only alert on HSTS bypass (max-age=0) — a concrete attack signal.
        The 'missing_security_headers' check has been removed because it fires
        on every HTTP response on the internet and generates massive false positives.
        Web server hardening is not an SSL Strip attack indicator.
        """
        try:
            hsts_header = headers.get('strict-transport-security', '')
            if hsts_header and 'max-age=0' in hsts_header:
                self._generate_alert("hsts_bypass_attempt", {
                    "session_key": session_key,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "hsts_header": hsts_header,
                    "severity": "high",
                    "description": "HSTS bypass attempt detected (max-age=0)"
                })

        except Exception as e:
            self.logger.error(f"Error checking SSL downgrade patterns: {e}")

    def _check_html_modifications(self, html_content: str, session_key: str, src_ip: str, dst_ip: str):
        try:
            suspicious_js_patterns = [
                r'location\.protocol\s*=\s*["\']http:',
                r'window\.location\s*=\s*["\']http:',
                r'href\s*=\s*["\']http://.*["\']',
                r'action\s*=\s*["\']http://.*["\']',
                r'replace\(["\']https:["\'],\s*["\']http:["\']',
            ]

            for pattern in suspicious_js_patterns:
                if re.search(pattern, html_content, re.IGNORECASE):
                    self._generate_alert("suspicious_link_modification", {
                        "session_key": session_key,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "pattern_matched": pattern,
                        "severity": "high",
                        "description": "Suspicious JavaScript modifying HTTPS links detected"
                    })
                    break

        except Exception as e:
            self.logger.error(f"Error checking HTML modifications: {e}")

    def _analyze_https_traffic(self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        try:
            session_key = self._make_session_key(src_ip, dst_ip, src_port, dst_port)

            self.https_sessions[session_key] = {
                "timestamp": datetime.now(),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port
            }

        except Exception as e:
            self.logger.error(f"Error analyzing HTTPS traffic: {e}")

    def _analyze_ssl_handshake(self, packet, src_ip: str, dst_ip: str, src_port: int, dst_port: int):
        """
        Detect genuine TLS/SSL downgrade attacks.

        Only alerts on SSL 3.0 (0x0300) — a deprecated, broken protocol with
        known vulnerabilities (POODLE, etc.) that no legitimate server should
        use.  TLS 1.0 and TLS 1.1 are still used by many legitimate servers
        (load balancers, CDNs, older hardware) and are NOT reliable attack
        indicators on their own.

        A 5-minute per-destination cooldown prevents alert spam when the same
        server sends multiple handshake packets in quick succession.
        """
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load

                if len(payload) > 5:
                    content_type = payload[0]

                    if content_type == 0x16:  # TLS Handshake record
                        record_version = (payload[1] << 8) | payload[2]

                        # Only alert for SSL 3.0 (0x0300) — broken, no legitimate use.
                        # TLS 1.0 (0x0301) and TLS 1.1 (0x0302) are excluded because
                        # they appear in normal traffic from CDNs and older servers.
                        if record_version == 0x0300:
                            now = datetime.now()
                            last_alert = self._tls_downgrade_cooldown.get(dst_ip)
                            if last_alert and (now - last_alert).total_seconds() < 300:
                                return  # Cooldown active — skip duplicate alert
                            self._tls_downgrade_cooldown[dst_ip] = now

                            # Prune cooldown table to prevent unbounded memory growth
                            if len(self._tls_downgrade_cooldown) > 500:
                                cutoff = now
                                self._tls_downgrade_cooldown = {
                                    ip: ts for ip, ts in self._tls_downgrade_cooldown.items()
                                    if (cutoff - ts).total_seconds() < 300
                                }

                            self._generate_alert("tls_downgrade_attempt", {
                                "src_ip": src_ip,
                                "dst_ip": dst_ip,
                                "tls_version": "SSL3.0",
                                "severity": "high",
                                "description": f"Deprecated SSL 3.0 detected from {src_ip} to {dst_ip} — possible POODLE/downgrade attack"
                            })

        except Exception as e:
            self.logger.error(f"Error analyzing SSL handshake: {e}")

    def _is_sensitive_site(self, hostname: str) -> bool:
        sensitive_keywords = [
            'bank', 'login', 'auth', 'secure', 'payment', 'paypal',
            'credit', 'account', 'admin', 'portal', 'mail', 'webmail'
        ]

        hostname_lower = hostname.lower()
        return any(keyword in hostname_lower for keyword in sensitive_keywords)

    # ------------------------------------------------------------------
    # Alert routing
    # ------------------------------------------------------------------
    def _generate_alert(self, alert_type: str, details: Dict):
        try:
            if self.dns_spoof_detected and alert_type in {
                "https_to_http_redirect",
                "https_over_http",
                "tls_downgrade_attempt"
            }:
                if details.get("severity") in {"info", "low", "medium"}:
                    details["severity"] = "critical"
                    details["description"] = details.get("description", "") + " (correlated with DNS spoofing)"

            source_ip = details.get("src_ip") or details.get("source_ip")
            target_ip = details.get("dst_ip") or details.get("target_ip")
            details.setdefault("client_ip", source_ip)
            severity = details.get("severity", "medium")
            description = details.get("description")

            if self._alert_callback is not None:
                self._alert_callback(
                    detector="ssl_strip",
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
                    "detector": "ssl_strip",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"SSL Strip Alert: {alert}")

            if getattr(self, "_network_monitor", None) is not None and source_ip:
                try:
                    self._network_monitor.record_suspicious(source_ip, alert_type)
                except Exception:
                    pass

            return details
        except Exception as e:
            self.logger.error(f"Error generating SSL alert: {e}")

    # ------------------------------------------------------------------
    # Data access for /api/ssl
    # ------------------------------------------------------------------
    def sessions_data(self) -> List[dict]:
        """Return current HTTPS/HTTP session state for the SSL Strip monitor."""
        result = []
        seen = set()
        now = datetime.now()

        for key, sess in list(self.https_sessions.items())[:50]:
            host = sess.get("dst_ip", "")
            status = "secure"
            details = None
            for hk, hs in list(self.http_sessions.items())[:200]:
                if hs.get("dst_ip") == host:
                    status = "downgraded"
                    details = "HTTPS session observed alongside HTTP traffic"
                    break
            entry = {
                "id": key if isinstance(key, str) else "|".join(key),
                "host": host,
                "ip": sess.get("dst_ip", ""),
                "status": status,
                "has_hsts": True,
                "timestamp": sess.get("timestamp", now).isoformat() if isinstance(sess.get("timestamp"), datetime) else str(sess.get("timestamp", "")),
                "details": details,
            }
            if entry["id"] not in seen:
                seen.add(entry["id"])
                result.append(entry)

        # Add detected warning sessions from http_sessions with sensitive hosts.
        for key, sess in list(self.http_sessions.items())[:50]:
            entry_id = key if isinstance(key, str) else "|".join(key)
            if entry_id in seen:
                continue
            host = sess.get("dst_ip", "")
            if self._is_sensitive_site(host or ""):
                result.append({
                    "id": entry_id,
                    "host": host,
                    "ip": sess.get("dst_ip", ""),
                    "status": "stripped",
                    "has_hsts": False,
                    "timestamp": sess.get("timestamp", now).isoformat() if isinstance(sess.get("timestamp"), datetime) else str(sess.get("timestamp", "")),
                    "details": "Sensitive traffic over HTTP",
                })
                seen.add(entry_id)

        return result

    def warnings_data(self) -> List[dict]:
        """Return SSL strip warnings from alerts raised by this detector."""
        warnings = []
        try:
            alerts = self.alert_manager.recent_alerts(limit=100) if self.alert_manager else []
            for a in alerts:
                if a.get("detector") == "ssl_strip":
                    details = a.get("details", {})
                    warnings.append({
                        "host": details.get("host") or details.get("dst_ip") or a.get("target_ip") or "",
                        "type": a.get("alert_type"),
                        "message": a.get("description"),
                        "severity": a.get("severity"),
                    })
        except Exception as exc:
            self.logger.error(f"Error building SSL warnings: {exc}")
        return warnings

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting SSL strip detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        self.is_running = False
        self.logger.info("Stopping SSL strip detector")

    def status(self) -> str:
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        return {
            "detector": "ssl_strip",
            "status": self.status(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "uptime_seconds": int((datetime.utcnow() - self._started_at).total_seconds())
            if self._started_at else 0,
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "last_error": self._last_error,
            "thread_alive": bool(self.monitor_thread and self.monitor_thread.is_alive()),
            "http_sessions": len(self.http_sessions),
            "https_sessions": len(self.https_sessions),
        }

    def get_thread(self) -> Optional[threading.Thread]:
        return self.monitor_thread

    def statistics(self) -> dict:
        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "http_sessions": len(self.http_sessions),
            "https_sessions": len(self.https_sessions),
        }

    def start_monitoring(self):
        self.start()

    def stop_monitoring(self):
        self.stop()
