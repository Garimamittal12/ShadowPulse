import scapy.all as scapy
import threading
import logging
import re
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional
from urllib.parse import unquote

try:
    from core.alert_manager import AlertManager
except ImportError:
    AlertManager = None


class HTTPInjectionDetector:
    """HTTP Injection Attack Detector.

    Detection logic is preserved exactly as-is. The detector no longer starts
    its own packet capture; it receives packets via ``handle_packet()``.
    """

    def __init__(self, interface: str = None):
        self.interface = interface
        self.http_sessions = defaultdict(dict)
        self.injection_patterns = self._load_injection_patterns()
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

    def _load_injection_patterns(self) -> Dict[str, List[str]]:
        return {
            "sql_injection": [
                r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                r"(\%27)|(\')|(\")|(\%22)",
                r"union.*select",
                r"insert.*into",
                r"delete.*from",
                r"drop.*table",
                r"exec(\s|\+)+(s|x)p\w+",
                r"or\s+1\s*=\s*1",
                r"and\s+1\s*=\s*1",
                r"having\s+1\s*=\s*1"
            ],
            "xss_injection": [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"vbscript:",
                r"onload\s*=",
                r"onerror\s*=",
                r"onclick\s*=",
                r"onmouseover\s*=",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>",
                r"<applet[^>]*>",
                r"<meta[^>]*>",
                r"<img[^>]*onerror[^>]*>",
                r"eval\s*\(",
                r"setTimeout\s*\(",
                r"setInterval\s*\("
            ],
            "command_injection": [
                r"[;&|`]\s*(ls|dir|cat|type|more|less)",
                r"[;&|`]\s*(rm|del|mv|copy|cp)",
                r"[;&|`]\s*(nc|netcat|telnet|ssh)",
                r"[;&|`]\s*(wget|curl|fetch)",
                r"[;&|`]\s*(ps|top|kill|killall)",
                r"[;&|`]\s*(id|whoami|groups)",
                r"\$\(.*\)",
                r"`.*`",
                r"\|\s*(nc|netcat|sh|bash|cmd)",
                r"&&\s*(wget|curl)"
            ],
            "ldap_injection": [
                r"\*\)\(.*=",
                r"\)\(\|.*=",
                r"\)\(&.*=",
                r"\*\)\(.*\|\(",
                r"\*\)\(.*&\("
            ],
            "xpath_injection": [
                r"(\x27|\')(\s)*(or|and)(\s)*(\x27|\')(\s)*=(\s)*(\x27|\')",
                r"(\x22|\")(\s)*(or|and)(\s)*(\x22|\")(\s)*=(\s)*(\x22|\")",
                r"or\s+1\s*=\s*1",
                r"and\s+1\s*=\s*1"
            ]
        }

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
        self.detect_http_injection(packet)

    # ------------------------------------------------------------------
    # Detection logic (preserved unchanged)
    # ------------------------------------------------------------------
    def detect_http_injection(self, packet):
        try:
            if packet.haslayer(scapy.Raw):
                payload = packet[scapy.Raw].load.decode('utf-8', errors='ignore')
                src_ip = packet[scapy.IP].src if packet.haslayer(scapy.IP) else "unknown"
                dst_ip = packet[scapy.IP].dst if packet.haslayer(scapy.IP) else "unknown"

                if payload.startswith(('GET ', 'POST ', 'PUT ', 'DELETE ', 'HEAD ', 'OPTIONS ')):
                    self._analyze_http_request(payload, src_ip, dst_ip)
                elif payload.startswith('HTTP/'):
                    self._analyze_http_response(payload, src_ip, dst_ip)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in HTTP injection detection: {e}")

    def _analyze_http_request(self, payload: str, src_ip: str, dst_ip: str):
        try:
            lines = payload.split('\r\n')
            request_line = lines[0] if lines else ""
            headers = {}
            body = ""

            in_body = False
            for line in lines[1:]:
                if not line.strip() and not in_body:
                    in_body = True
                    continue

                if in_body:
                    body += line + "\n"
                else:
                    if ':' in line:
                        key, value = line.split(':', 1)
                        headers[key.strip().lower()] = value.strip()

            parts = request_line.split()
            if len(parts) >= 2:
                method = parts[0]
                url = parts[1]

                decoded_url = unquote(url)
                decoded_body = unquote(body)

                self._check_injection_patterns(decoded_url, "url", src_ip, dst_ip, method)

                if body:
                    self._check_injection_patterns(decoded_body, "body", src_ip, dst_ip, method)

                for header_name, header_value in headers.items():
                    if header_name in ['user-agent', 'referer', 'cookie', 'x-forwarded-for']:
                        decoded_header = unquote(header_value)
                        self._check_injection_patterns(decoded_header, f"header_{header_name}", src_ip, dst_ip, method)

                self._detect_suspicious_request_patterns(method, decoded_url, headers, decoded_body, src_ip, dst_ip)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing HTTP request: {e}")

    def _analyze_http_response(self, payload: str, src_ip: str, dst_ip: str):
        try:
            lines = payload.split('\r\n')
            status_line = lines[0] if lines else ""

            sql_error_patterns = [
                r"SQL syntax.*MySQL",
                r"Warning.*mysql_.*",
                r"valid MySQL result",
                r"MySqlClient\.",
                r"PostgreSQL.*ERROR",
                r"Warning.*pg_.*",
                r"valid PostgreSQL result",
                r"Npgsql\.",
                r"Driver.*SQL.*Server",
                r"OLE DB.*SQL Server",
                r"(\[SQL Server\])",
                r"ODBC.*SQL Server",
                r"SQLServer JDBC Driver",
                r"SqlException",
                r"Oracle error",
                r"Oracle.*Driver",
                r"Warning.*oci_.*",
                r"Warning.*ora_.*"
            ]

            for pattern in sql_error_patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    self._generate_alert("sql_error_disclosure", {
                        "source_ip": dst_ip,
                        "target_ip": src_ip,
                        "pattern_matched": pattern,
                        "severity": "medium",
                        "description": "SQL error message detected in HTTP response"
                    })
                    break

            # MITM HTML/JS injection focus: detect signatures of content that
            # was injected by an attacker into a legitimate HTTP response.
            self._detect_mitm_injection(payload, src_ip, dst_ip)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing HTTP response: {e}")

    def _detect_mitm_injection(self, payload: str, server_ip: str, client_ip: str):
        """Detect HTML/JS injection into HTTP responses (MITM attack).

        A MITM attacker often injects a small script tag, hidden iframe, or
        JavaScript snippet into a legitimate HTTP response. These injections
        typically appear right before the closing </body> or </html> tag, or
        are appended to the end of the payload.
        """
        try:
            # Parse headers and body from the HTTP response.
            parts = payload.split('\r\n\r\n', 1)
            if len(parts) < 2:
                return
            headers_raw, body = parts
            headers = {}
            for line in headers_raw.split('\r\n')[1:]:
                if ':' in line:
                    k, v = line.split(':', 1)
                    headers[k.strip().lower()] = v.strip()

            content_type = headers.get('content-type', '').lower()
            if 'text/html' not in content_type and 'application/javascript' not in content_type:
                return

            # Track the baseline body for this server+client pair so we can
            # detect when content is modified between responses.
            session_key = f"{server_ip}->{client_ip}"
            if not hasattr(self, "_response_baselines"):
                self._response_baselines = {}

            # 1. Look for injected script/iframe markers that are not part of
            #    the original page (heuristic signatures).
            injected_markers = [
                # Small inline scripts commonly injected by MITM tools.
                (r"<script[^>]*>\s*</script>", "empty_inline_script"),
                (r"<script[^>]+src=[\"'][^\"']*\.(?:js|txt)[\"'][^>]*></script>", "external_script_tag"),
                (r"<iframe[^>]+src=[\"'][^\"']+[\"'][^>]*>\s*</iframe>", "hidden_iframe"),
                (r"<script[^>]*>\s*(?:window\.onload|document\.cookie|fetch\(|XMLHttpRequest)", "js_tracking_code"),
                (r"<img[^>]+src=[\"'][^\"']+[\"'][^>]*width=[\"']?[01][\"']?[^>]*>", "tracking_pixel"),
                (r"<meta[^>]+http-equiv=[\"']refresh[\"'][^>]*>", "meta_refresh_redirect"),
            ]

            for pattern, marker_name in injected_markers:
                if re.search(pattern, body, re.IGNORECASE):
                    self._generate_alert("mitm_html_injection", {
                        "source_ip": server_ip,
                        "target_ip": client_ip,
                        "marker": marker_name,
                        "pattern_matched": pattern,
                        "content_sample": body[:300],
                        "severity": "high",
                        "description": f"Possible MITM HTML injection detected: {marker_name}"
                    })

            # 2. Detect injection right before </body> or </html> (common MITM insertion point).
            lower_body = body.lower()
            if '</body>' in lower_body or '</html>' in lower_body:
                # Find the last occurrence of the closing tag.
                close_idx = max(lower_body.rfind('</body>'), lower_body.rfind('</html>'))
                trailing = body[close_idx:]
                # If there's executable content after the closing tag, it's suspicious.
                if re.search(r"<script|javascript:|onload=|onerror=", trailing, re.IGNORECASE):
                    self._generate_alert("mitm_trailing_injection", {
                        "source_ip": server_ip,
                        "target_ip": client_ip,
                        "trailing_content": trailing[:300],
                        "severity": "high",
                        "description": "Executable content found after HTML closing tag - possible MITM injection"
                    })

            # 3. Track response body size to detect unexpected inflation.
            #    A MITM-injected page will typically be larger than the baseline.
            body_size = len(body)
            baseline = self._response_baselines.get(session_key)
            if baseline is not None:
                base_size = baseline.get("size", 0)
                # If the body is >50% larger than baseline and contains script markers.
                if base_size > 0 and body_size > base_size * 1.5 and re.search(r"<script|iframe", body, re.IGNORECASE):
                    self._generate_alert("mitm_body_inflation", {
                        "source_ip": server_ip,
                        "target_ip": client_ip,
                        "baseline_size": base_size,
                        "current_size": body_size,
                        "severity": "medium",
                        "description": f"HTTP response body inflated {base_size} -> {body_size} bytes with script content"
                    })
            else:
                # Seed the baseline with the max observed size (more stable).
                self._response_baselines[session_key] = {"size": body_size}
            # Update baseline to the max seen (avoid shrinking baseline).
            if baseline is None or body_size > baseline.get("size", 0):
                self._response_baselines[session_key] = {"size": body_size}

            # Bound memory growth.
            if len(self._response_baselines) > 500:
                # Keep only the most recent 250 entries.
                items = list(self._response_baselines.items())
                self._response_baselines = dict(items[-250:])

        except Exception as e:
            self.logger.error(f"Error detecting MITM injection: {e}")

    def _check_injection_patterns(self, content: str, location: str, src_ip: str, dst_ip: str, method: str):
        try:
            for injection_type, patterns in self.injection_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        self._generate_alert("injection_attempt", {
                            "injection_type": injection_type,
                            "source_ip": src_ip,
                            "target_ip": dst_ip,
                            "http_method": method,
                            "location": location,
                            "pattern_matched": pattern,
                            "content_sample": content[:200],
                            "severity": self._get_severity_by_type(injection_type),
                            "description": f"{injection_type.replace('_', ' ').title()} attempt detected in {location}"
                        })
                        return

        except Exception as e:
            self.logger.error(f"Error checking injection patterns: {e}")

    def _detect_suspicious_request_patterns(self, method: str, url: str, headers: Dict, body: str, src_ip: str, dst_ip: str):
        try:
            traversal_patterns = [
                r"\.\.[\\/]",
                r"%2e%2e[\\/]",
                r"\.\.%2f",
                r"\.\.%5c",
                r"%252e%252e",
                r"..%c0%af",
                r"..%c1%9c"
            ]

            for pattern in traversal_patterns:
                if re.search(pattern, url, re.IGNORECASE):
                    self._generate_alert("directory_traversal", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "http_method": method,
                        "url": url,
                        "pattern_matched": pattern,
                        "severity": "high",
                        "description": "Directory traversal attempt detected"
                    })
                    break

            file_inclusion_patterns = [
                r"(file|php|data)://",
                r"expect://",
                r"zip://",
                r"include\s*\(",
                r"require\s*\(",
                r"include_once\s*\(",
                r"require_once\s*\("
            ]

            content_to_check = url + " " + body
            for pattern in file_inclusion_patterns:
                if re.search(pattern, content_to_check, re.IGNORECASE):
                    self._generate_alert("file_inclusion", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "http_method": method,
                        "url": url,
                        "pattern_matched": pattern,
                        "severity": "high",
                        "description": "File inclusion attempt detected"
                    })
                    break

            if '&' in url:
                param_count = url.count('&') + 1
                if param_count > 50:
                    self._generate_alert("parameter_pollution", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "http_method": method,
                        "parameter_count": param_count,
                        "severity": "medium",
                        "description": f"Excessive parameters detected: {param_count}"
                    })

            user_agent = headers.get('user-agent', '').lower()
            suspicious_ua_patterns = [
                r"sqlmap",
                r"havij",
                r"nmap",
                r"nikto",
                r"w3af",
                r"acunetix",
                r"netsparker",
                r"burp",
                r"paros",
                r"webscarab",
                r"python-requests",
                r"curl",
                r"wget"
            ]

            for pattern in suspicious_ua_patterns:
                if re.search(pattern, user_agent):
                    self._generate_alert("suspicious_user_agent", {
                        "source_ip": src_ip,
                        "target_ip": dst_ip,
                        "user_agent": user_agent,
                        "pattern_matched": pattern,
                        "severity": "medium",
                        "description": "Suspicious User-Agent detected"
                    })
                    break

        except Exception as e:
            self.logger.error(f"Error detecting suspicious patterns: {e}")

    def _get_severity_by_type(self, injection_type: str) -> str:
        severity_map = {
            "sql_injection": "high",
            "xss_injection": "high",
            "command_injection": "critical",
            "ldap_injection": "high",
            "xpath_injection": "high"
        }
        return severity_map.get(injection_type, "medium")

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
                    detector="http_injection",
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
                    "detector": "http_injection",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"HTTP Injection Alert: {alert}")

            if getattr(self, "_network_monitor", None) is not None and source_ip:
                try:
                    self._network_monitor.record_suspicious(source_ip, alert_type)
                except Exception:
                    pass

            return details
        except Exception as e:
            self.logger.error(f"Error generating HTTP alert: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting HTTP injection detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        self.is_running = False
        self.logger.info("Stopping HTTP injection detector")

    def status(self) -> str:
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        return {
            "detector": "http_injection",
            "status": self.status(),
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "uptime_seconds": int((datetime.utcnow() - self._started_at).total_seconds())
            if self._started_at else 0,
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "last_error": self._last_error,
            "thread_alive": bool(self.monitor_thread and self.monitor_thread.is_alive()),
        }

    def get_thread(self) -> Optional[threading.Thread]:
        return self.monitor_thread

    def statistics(self) -> dict:
        return {
            "packets_processed": self._packets_processed,
            "alerts_generated": self._alerts_generated,
            "http_sessions": len(self.http_sessions),
        }

    def start_monitoring(self):
        self.start()

    def stop_monitoring(self):
        self.stop()
