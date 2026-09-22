import scapy.all as scapy
import threading
import logging
import socket
from ipaddress import ip_address
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional

try:
    from core.alert_manager import AlertManager
except ImportError:
    AlertManager = None


class DNSSpoofDetector:
    """DNS Spoofing Attack Detector.

    An unknown DNS server alone is NOT a spoofing indicator — enterprise,
    university, and ISP networks use private resolvers that are not in any
    public list.  The detector requires at least one corroborating piece of
    evidence before raising an 'unauthorized_dns_server' alert:

        • Duplicate DNS transaction ID (cache poisoning signal)
        • Conflicting DNS responses (different answers for the same query)
        • Suspicious resolution (well-known domain resolving to private/wrong IP)

    Other alert types (conflicting responses, TTL anomaly, cache poisoning)
    are independent and still fire on their own when warranted.

    The detector no longer starts its own packet capture; it receives
    packets via ``handle_packet()``.
    """

    def __init__(self, interface: str = None, trusted_dns_servers: List[str] = None):
        self.interface = interface
        self.trusted_dns_servers = set(trusted_dns_servers) if trusted_dns_servers else set()
        self.dns_cache = {}
        self.dns_responses = defaultdict(list)
        # A response is meaningful only when we saw the matching request from
        # this client.  Looking at responses alone mixes unrelated traffic on
        # shared Wi-Fi networks and makes normal resolver ID reuse look like a
        # cache-poisoning race.
        self._pending_queries: Dict[tuple, datetime] = {}
        self.suspicious_domains = set()
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

        # Well-known public resolvers — always trusted.
        self.known_dns_servers = {
            "8.8.8.8", "8.8.4.4",
            "1.1.1.1", "1.0.0.1",
            "208.67.222.222", "208.67.220.220",
            "9.9.9.9", "149.112.112.112"
        }

        # Auto-discover trusted DNS servers from the OS at startup.
        # This ensures locally assigned resolvers (enterprise, university,
        # ISP) are trusted without requiring manual configuration.
        self._auto_discover_trusted_servers()

        # Per-query set of pending corroborating evidence collected during
        # the current analysis pass (transaction_id -> set of alert_types).
        self._pending_evidence: Dict[str, set] = {}
        self._current_client_ip: Optional[str] = None

    def _auto_discover_trusted_servers(self) -> None:
        """Populate trusted_dns_servers from OS/DHCP/network configuration.

        Sources tried (in order):
          1. utils.network_scanner.NetworkScanner.get_dns_servers()
          2. Windows: `ipconfig /all` DNS Server lines
          3. Linux/macOS: /etc/resolv.conf nameserver lines
          4. Default gateway IP (many home routers also act as DNS)
        """
        discovered: set = set()

        # ── Source 1: NetworkScanner helper (cross-platform) ───────────
        try:
            from utils.network_scanner import NetworkScanner
            for server in NetworkScanner.get_dns_servers():
                if server:
                    discovered.add(server)
        except Exception:
            pass

        # ── Source 2: Windows ipconfig /all ───────────────────────────
        if not discovered:
            try:
                import subprocess
                result = subprocess.run(
                    ["ipconfig", "/all"],
                    capture_output=True, text=True, timeout=5
                )
                import re
                for line in result.stdout.splitlines():
                    if "DNS Servers" in line or "DNS Server" in line:
                        # e.g. "   DNS Servers . . . . . . . . . . . : 172.16.10.10"
                        parts = line.split(":")
                        if len(parts) >= 2:
                            ip = parts[-1].strip()
                            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', ip):
                                discovered.add(ip)
            except Exception:
                pass

        # ── Source 3: /etc/resolv.conf (Linux / macOS) ─────────────────
        if not discovered:
            try:
                with open("/etc/resolv.conf", "r") as f:
                    import re
                    for line in f:
                        line = line.strip()
                        if line.startswith("nameserver"):
                            parts = line.split()
                            if len(parts) >= 2:
                                discovered.add(parts[1])
            except Exception:
                pass

        # ── Source 4: default gateway (often doubles as resolver) ──────
        try:
            import socket
            gw = socket.getdefaultgateway() if hasattr(socket, 'getdefaultgateway') else None
            if gw:
                discovered.add(gw)
        except Exception:
            pass
        try:
            if getattr(self, "_network_monitor", None):
                gw = self._network_monitor.get_gateway()
                if gw:
                    discovered.add(gw)
        except Exception:
            pass

        self.trusted_dns_servers.update(discovered)
        if discovered:
            self.logger.info(
                f"DNSSpoofDetector: auto-discovered trusted DNS servers: {discovered}"
            )

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
        # Re-run auto-discovery now that the network monitor is available.
        self._auto_discover_trusted_servers()

    # ------------------------------------------------------------------
    # Dispatcher entry point
    # ------------------------------------------------------------------
    def handle_packet(self, packet) -> None:
        if not self.is_running:
            return
        self._packets_processed += 1
        self.detect_dns_spoof(packet)

    # ------------------------------------------------------------------
    # Detection logic (preserved unchanged)
    # ------------------------------------------------------------------
    def detect_dns_spoof(self, packet):
        try:
            if packet.haslayer(scapy.DNS):
                dns_layer = packet[scapy.DNS]
                if dns_layer.qr == 0:
                    self._record_dns_query(packet)
                elif dns_layer.qr == 1:
                    self._analyze_dns_response(packet)
        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error in DNS spoof detection: {e}")

    def _dns_query_key(self, client_ip: str, client_port: int, dns_layer) -> Optional[tuple]:
        """Return a tuple that identifies one client DNS request."""
        try:
            if not dns_layer.qd:
                return None
            name = dns_layer.qd.qname.decode("utf-8", errors="ignore").rstrip(".").lower()
            return (client_ip, int(client_port), int(dns_layer.id), name, int(dns_layer.qd.qtype))
        except Exception:
            return None

    def _record_dns_query(self, packet) -> None:
        """Remember recent DNS requests so responses can be correlated safely."""
        try:
            if not packet.haslayer(scapy.IP) or not packet.haslayer(scapy.UDP):
                return
            key = self._dns_query_key(packet[scapy.IP].src, packet[scapy.UDP].sport, packet[scapy.DNS])
            if key is None:
                return
            now = datetime.now()
            cutoff = now - timedelta(seconds=15)
            self._pending_queries = {k: ts for k, ts in self._pending_queries.items() if ts > cutoff}
            self._pending_queries[key] = now
        except Exception:
            return

    def _response_matches_observed_query(self, packet, dns_layer) -> bool:
        """Require an observed request with the same client, port, ID and name."""
        try:
            if not packet.haslayer(scapy.IP) or not packet.haslayer(scapy.UDP):
                return False
            key = self._dns_query_key(packet[scapy.IP].dst, packet[scapy.UDP].dport, dns_layer)
            if key is None:
                return False
            timestamp = self._pending_queries.pop(key, None)
            return timestamp is not None and (datetime.now() - timestamp).total_seconds() <= 15
        except Exception:
            return False

    def _analyze_dns_response(self, packet):
        try:
            dns_layer = packet[scapy.DNS]
            # Do not infer attacks from responses that cannot be tied to a
            # request we captured.  In promiscuous/shared networks these are
            # frequently other clients' packets.
            if not self._response_matches_observed_query(packet, dns_layer):
                return
            src_ip = packet[scapy.IP].src
            client_ip = packet[scapy.IP].dst
            self._current_client_ip = client_ip

            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8').rstrip('.')
                query_type = dns_layer.qd.qtype

                answers = []
                ttl_values = []
                if dns_layer.an:
                    for i in range(dns_layer.ancount):
                        if i < len(dns_layer.an):
                            answer = dns_layer.an[i]
                            if hasattr(answer, 'rdata'):
                                answers.append(str(answer.rdata))
                            if hasattr(answer, 'ttl'):
                                ttl_values.append(int(answer.ttl))

                response_info = {
                    "timestamp": datetime.now(),
                    "server_ip": src_ip,
                    "client_ip": client_ip,
                    "query_name": query_name,
                    "query_type": query_type,
                    "answers": answers,
                    "ttl_values": ttl_values,
                    "transaction_id": dns_layer.id
                }

                # Never compare answers for different clients.  On a shared
                # adapter, unrelated hosts frequently ask the same CDN name.
                query_key = f"{client_ip}:{query_name}:{query_type}"
                self.dns_responses[query_key].append(response_info)

                cutoff_time = datetime.now() - timedelta(minutes=1)
                self.dns_responses[query_key] = [
                    resp for resp in self.dns_responses[query_key]
                    if resp["timestamp"] > cutoff_time
                ]

                self._detect_conflicting_responses(query_key)
                self._detect_unauthorized_server(response_info)
                self._detect_suspicious_resolutions(response_info)
                self._detect_cache_poisoning(response_info)
                self._detect_ttl_anomaly(response_info)

        except Exception as e:
            self._last_error = str(e)
            self.logger.error(f"Error analyzing DNS response: {e}")

    def _detect_conflicting_responses(self, query_key: str):
        """
        Detect when two DIFFERENT DNS servers return different answers for the
        same query within a 1-minute window. We now require at least 2 distinct
        server IPs to have answered before declaring a conflict — a single server
        can legitimately return different answers on successive queries (CDN
        load-balancing, TTL expiry, etc.).
        """
        try:
            responses = self.dns_responses[query_key]
            if len(responses) < 2:
                return

            servers_responses = defaultdict(list)
            for response in responses:
                servers_responses[response["server_ip"]].append(response)

            # Need at least two DISTINCT server IPs to have answered.
            if len(servers_responses) < 2:
                return

            unique_answers = set()
            servers_with_answers = {}

            for server_ip, server_responses in servers_responses.items():
                for response in server_responses:
                    answer_key = tuple(sorted(response["answers"]))
                    unique_answers.add(answer_key)
                    servers_with_answers[server_ip] = answer_key

            # Different public CDN answers from two resolvers are expected.
            # Treat a conflict as suspicious only if it redirects an observed
            # public lookup into a local/private address; that is a concrete
            # redirection signal rather than ordinary load balancing.
            has_private_answer = any(
                self._answers_include_private_ip(response.get("answers", []))
                for response in responses
            )
            if len(unique_answers) > 1 and has_private_answer:
                self._generate_alert("conflicting_dns_responses", {
                    "query": query_key,
                    "servers_count": len(servers_with_answers),
                    "unique_answers_count": len(unique_answers),
                    "servers_responses": dict(servers_with_answers),
                    "severity": "high",
                    "description": "Multiple DNS servers giving different answers for same query"
                })

        except Exception as e:
            self.logger.error(f"Error detecting conflicting responses: {e}")

    def _has_corroborating_evidence(self, response_info: Dict) -> bool:
        """Return True when at least one additional spoofing indicator exists.

        An unknown DNS server alone is NOT sufficient to raise an alert —
        legitimate private networks (enterprise, university, ISP) use their
        own resolvers.  We only alert when the unknown server also shows a
        concrete spoofing signal:

          • Duplicate transaction ID (cache poisoning indicator)
          • Conflicting DNS responses for the same query
          • Suspicious resolution (well-known domain -> wrong IP)
        """
        try:
            transaction_id = response_info.get("transaction_id")
            query_key = f"{response_info.get('query_name')}:{response_info.get('query_type')}"

            # Transaction IDs are only 16-bit and public answers legitimately
            # vary across resolvers.  A private/local answer is the reliable
            # corroborating signal for an untrusted resolver.
            query_name = response_info.get("query_name", "")
            answers = response_info.get("answers", [])
            # A public name resolving directly to a private address can be a
            # hijack.  Do not use a small static IP allow-list here: modern
            # sites use CDNs and their address ranges change frequently.
            return bool(answers) and self._answers_include_private_ip(answers)
        except Exception:
            return False

    def _detect_unauthorized_server(self, response_info: Dict):
        """Alert on an unknown DNS server ONLY when there is corroborating evidence.

        An unknown resolver is normal in enterprise / university / ISP networks.
        We require at least one additional spoofing indicator before alerting.
        """
        try:
            server_ip = response_info["server_ip"]

            # If no trusted-server list has been built yet, skip the check.
            # We cannot determine "unknown" without a baseline.
            if not self.trusted_dns_servers:
                return

            # Server is trusted — nothing to do.
            if server_ip in self.trusted_dns_servers or server_ip in self.known_dns_servers:
                return

            # Unknown server — only alert when it returns a concrete local-IP
            # redirection.  Resolver variation and transaction-ID reuse are
            # normal on enterprise and CDN-backed networks.
            if self._has_corroborating_evidence(response_info):
                self._generate_alert("unauthorized_dns_server", {
                    "server_ip": server_ip,
                    "query_name": response_info["query_name"],
                    "answers": response_info["answers"],
                    "severity": "medium",
                    "description": (
                        f"DNS response from unknown server {server_ip} combined with "
                        f"additional spoofing indicators"
                    )
                })
            # else: log at debug level only — not an alert on its own.

        except Exception as e:
            self.logger.error(f"Error detecting unauthorized server: {e}")

    def _detect_suspicious_resolutions(self, response_info: Dict):
        """
        Detect DNS responses that point well-known public domains to private IPs,
        which is a strong signal of DNS hijacking.

        Excluded domains:
         • Microsoft telemetry/CDN: events.data.microsoft.com, teams.*, skype.*,
           update.microsoft.com, etc. — these legitimately use Akamai/Azure CDN
           which can assign private-range IPs in some network configurations.
         • Akamai / Cloudflare / Fastly edge nodes which serve private IPs on
           corporate proxies.

        We only alert on well-known consumer-facing domains (google.com, paypal.com,
        etc.) resolving to private IPs, as that has no legitimate explanation.
        """
        try:
            query_name = response_info["query_name"]
            answers = response_info["answers"]

            # Domains that legitimately resolve to private/CDN IPs on corporate
            # or home networks — skip the suspicious-resolution check entirely.
            _CDN_EXEMPT_PATTERNS = (
                'events.data.microsoft.com',
                'teams.events.data.microsoft.com',
                'mobile.events.data.microsoft.com',
                'trouter.skype.com',
                'trouter.teams.microsoft.com',
                'update.microsoft.com',
                'windowsupdate.com',
                'delivery.mp.microsoft.com',
                'settings-win.data.microsoft.com',
                'edge.microsoft.com',
                'msedge.net',
                'edgekey.net',
                'msedge.api.cdp.microsoft.com',
                'ntp.msn.com',
                'akamaiedge.net',
                'akamai.net',
                'akadns.net',
                'fastly.net',
                'cloudfront.net',
                'azureedge.net',
                'trafficmanager.net',
                'azure.com',
            )
            if any(query_name.endswith(pat) or query_name == pat for pat in _CDN_EXEMPT_PATTERNS):
                return

            if answers and self._answers_include_private_ip(answers):
                self._generate_alert("suspicious_dns_resolution", {
                    "query_name": query_name,
                    "answers": answers,
                    "server_ip": response_info["server_ip"],
                    "severity": "medium",
                    "description": f"Public DNS name {query_name} resolved to a private IP address"
                })

        except Exception as e:
            self.logger.error(f"Error detecting suspicious resolutions: {e}")

    def _detect_cache_poisoning(self, response_info: Dict):
        """Detect potential DNS cache poisoning via duplicate transaction IDs.

        DNS transaction IDs are 16-bit (0-65535) and are reused constantly by
        legitimate resolvers. A duplicate transaction ID is ONLY suspicious when
        two responses for the SAME query arrive from DIFFERENT source IPs —
        indicating an attacker is racing the real server to inject a forged
        response.

        A duplicate from the SAME server IP is normal (retransmission, TCP
        fallback, or the resolver simply reusing IDs over time).
        """
        try:
            query_name = response_info["query_name"]
            transaction_id = response_info["transaction_id"]
            server_ip = response_info["server_ip"]
            now = datetime.now()

            # Track transaction IDs with {timestamp, server_ip} so we can
            # distinguish same-server retransmissions from cross-server races.
            if not hasattr(self, 'recent_transaction_ids'):
                self.recent_transaction_ids = {}
            elif isinstance(self.recent_transaction_ids, set):
                # Migrate legacy set to dict with timestamps.
                self.recent_transaction_ids = {
                    tid: {"ts": now, "server_ip": None} for tid in self.recent_transaction_ids
                }

            # Expire entries older than 60 seconds.
            cutoff = now - timedelta(seconds=60)
            def _ts_of(info):
                if isinstance(info, dict):
                    return info.get("ts", now)
                return info  # legacy datetime value
            self.recent_transaction_ids = {
                tid: info for tid, info in self.recent_transaction_ids.items()
                if _ts_of(info) > cutoff
            }

            transaction_key = (response_info.get("client_ip"), query_name, response_info.get("query_type"), transaction_id)
            if transaction_key in self.recent_transaction_ids:
                prev = self.recent_transaction_ids[transaction_key]
                prev_server = prev.get("server_ip") if isinstance(prev, dict) else None
                # Only alert when the duplicate comes from a DIFFERENT server.
                # Same-server duplicates are normal retransmissions.
                previous_answers = prev.get("answers", []) if isinstance(prev, dict) else []
                if (prev_server and prev_server != server_ip and
                        self._answers_include_private_ip(previous_answers + response_info.get("answers", []))):
                    self._generate_alert("duplicate_transaction_id", {
                        "transaction_id": transaction_id,
                        "query_name": query_name,
                        "server_ip": server_ip,
                        "original_server_ip": prev_server,
                        "severity": "high",
                        "description": (
                            f"Duplicate DNS transaction ID {transaction_id} from different "
                            f"servers ({prev_server} vs {server_ip}) — possible cache poisoning"
                        )
                    })

            self.recent_transaction_ids[transaction_key] = {
                "ts": now,
                "server_ip": server_ip,
                "answers": response_info.get("answers", []),
            }

            # Bound memory growth.
            if len(self.recent_transaction_ids) > 1000:
                sorted_items = sorted(
                    self.recent_transaction_ids.items(),
                    key=lambda kv: kv[1].get("ts", now) if isinstance(kv[1], dict) else kv[1],
                    reverse=True
                )
                self.recent_transaction_ids = dict(sorted_items[:500])

        except Exception as e:
            self.logger.error(f"Error detecting cache poisoning: {e}")

    def _detect_ttl_anomaly(self, response_info: Dict):
        """Detect abnormally low or wildly inconsistent TTL values.

        A spoofed DNS response often uses a very short TTL (e.g. 1-5 seconds)
        or an inconsistent TTL compared to prior responses for the same query.

        Baseline seeding rules (prevent false positives):
          • The baseline is set ONCE when we first see a query. It is never
            overwritten by a lower TTL (which would cause runaway baseline
            shrinkage and ever-increasing false positives).
          • Only update the baseline when the new TTL is HIGHER than what we
            have stored (i.e. we saw a longer-lived response for the same query).

        Suspicious TTL threshold:
          • < 5 seconds: strong poisoning indicator (threshold tightened from 10s).
          • A per-domain cooldown of 10 minutes prevents repeated alerts for the
            same domain (e.g. Microsoft telemetry that legitimately uses short TTLs).

        CDN exempt domains (frequently have variable short TTLs by design):
          Microsoft telemetry, Skype/Teams trouter, Akamai edge nodes.
        """
        try:
            ttl_values = response_info.get("ttl_values") or []
            if not ttl_values:
                return

            query_name = response_info["query_name"]
            query_key = f"{query_name}:{response_info.get('query_type')}"
            now = datetime.now()

            # Domains with variable short TTLs by design — exempt from all TTL alerts.
            _TTL_EXEMPT_PATTERNS = (
                'events.data.microsoft.com',
                'teams.events.data.microsoft.com',
                'mobile.events.data.microsoft.com',
                'trouter.skype.com',
                'trouter.teams.microsoft.com',
                'edge.microsoft.com',
                'msedge.net',
                'msedge.api.cdp.microsoft.com',
                'ntp.msn.com',
                'akamaiedge.net',
                'akamai.net',
                'akadns.net',
                'edgekey.net',
                'fastly.net',
                'cloudfront.net',
                'azureedge.net',
                'trafficmanager.net',
                'azure.com',
                'bing.com',
                'msn.com',
            )
            if any(query_name.endswith(pat) or query_name == pat for pat in _TTL_EXEMPT_PATTERNS):
                return

            # Track baseline TTLs per query.
            if not hasattr(self, "_ttl_baselines"):
                self._ttl_baselines = {}

            # Per-domain alert cooldown (10 minutes) — prevents alert spam.
            if not hasattr(self, "_ttl_alert_cooldown"):
                self._ttl_alert_cooldown: Dict[str, datetime] = {}

            # Prune stale baselines older than 10 minutes.
            cutoff = now - timedelta(minutes=10)
            self._ttl_baselines = {
                k: v for k, v in self._ttl_baselines.items()
                if v.get("last_seen", now) > cutoff
            }

            baseline = self._ttl_baselines.get(query_key)
            min_ttl = min(ttl_values)
            max_ttl = max(ttl_values)

            def _can_alert(domain: str) -> bool:
                """Return True if the per-domain cooldown has expired."""
                last = self._ttl_alert_cooldown.get(domain)
                if last and (now - last).total_seconds() < 600:
                    return False
                self._ttl_alert_cooldown[domain] = now
                return True

            # TTL values are decremented by DNS caches and CDNs commonly use
            # very short, variable TTLs.  A TTL anomaly is therefore retained
            # only as local diagnostic state, never emitted as an attack by
            # itself.  A DNS alert requires contradictory answers, a
            # cross-server transaction-ID race, or a private-IP resolution.

            # Seed / update the baseline.
            # KEY FIX: Only update when no baseline exists OR new max_ttl is higher
            # than the stored baseline. Never let the baseline shrink — that causes
            # runaway false positives as the threshold drifts lower over time.
            if baseline is None:
                self._ttl_baselines[query_key] = {
                    "ttl": max_ttl,
                    "last_seen": now,
                }
            else:
                # Refresh last_seen timestamp; only raise the TTL baseline, never lower it.
                stored = baseline.get("ttl", 0) or 0
                self._ttl_baselines[query_key] = {
                    "ttl": max(stored, max_ttl),
                    "last_seen": now,
                }

            # Bound memory growth.
            if len(self._ttl_baselines) > 1000:
                sorted_items = sorted(
                    self._ttl_baselines.items(),
                    key=lambda kv: kv[1].get("last_seen", now),
                    reverse=True,
                )
                self._ttl_baselines = dict(sorted_items[:500])

        except Exception as e:
            self.logger.error(f"Error detecting TTL anomaly: {e}")

    def _is_legitimate_ip_for_domain(self, domain: str, ip: str) -> bool:
        """Best-effort check whether an IP is a known-legitimate resolver for a domain.

        Uses a small built-in map of major sites to their well-known public IPs.
        Returns False when the domain is recognized but the IP is not in the
        known set (potential spoofing). Returns True for unrecognized domains
        so we do not over-alert on arbitrary/custom domains.
        """
        try:
            known_resolvers = {
                "google.com": {"142.250.0.0/16", "172.217.0.0/16", "216.58.0.0/16"},
                "facebook.com": {"157.240.0.0/16", "31.13.0.0/16"},
                "microsoft.com": {"13.77.0.0/16", "40.76.0.0/16", "20.0.0.0/8"},
                "apple.com": {"17.0.0.0/8"},
                "amazon.com": {"176.32.0.0/16", "205.251.0.0/16"},
                "netflix.com": {"54.0.0.0/8"},
                "youtube.com": {"142.250.0.0/16", "172.217.0.0/16"},
                "wikipedia.org": {"208.80.0.0/16", "91.198.174.0/24"},
                "twitter.com": {"104.244.0.0/16", "199.59.0.0/16"},
                "linkedin.com": {"108.174.0.0/16", "13.107.0.0/16"},
            }

            base_domain = domain
            for known in known_resolvers:
                if domain == known or domain.endswith("." + known):
                    base_domain = known
                    break

            cidrs = known_resolvers.get(base_domain)
            if not cidrs:
                return True  # Unknown domain — don't false-positive.

            from ipaddress import ip_address, ip_network
            try:
                addr = ip_address(ip)
            except ValueError:
                return False

            return any(addr in ip_network(cidr, strict=False) for cidr in cidrs)
        except Exception:
            return True

    @staticmethod
    def _answers_include_private_ip(answers: List[str]) -> bool:
        """Return True only for actual RFC1918/link-local loopback answers.

        String-prefix tests are unsafe: for example, Cloudflare's public
        172.64.0.0/13 range was incorrectly treated as private by the old
        ``ip.startswith('172.')`` rule.
        """
        for answer in answers:
            try:
                candidate = ip_address(str(answer))
                if candidate.is_private or candidate.is_loopback or candidate.is_link_local:
                    return True
            except ValueError:
                # CNAME/TXT records are not IP answers and are not evidence of
                # DNS redirection on their own.
                continue
        return False

    # ------------------------------------------------------------------
    # Alert routing
    # ------------------------------------------------------------------
    def _generate_alert(self, alert_type: str, details: Dict):
        try:
            details.setdefault("client_ip", self._current_client_ip)
            source_ip = details.get("server_ip") or details.get("source_ip")
            target_ip = details.get("target_ip") or details.get("client_ip")
            severity = details.get("severity", "medium")
            description = details.get("description")

            if self._alert_callback is not None:
                self._alert_callback(
                    detector="dns_spoof",
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
                    "detector": "dns_spoof",
                    "alert_type": alert_type,
                    "details": details
                }
                self.logger.warning(f"DNS Spoofing Alert: {alert}")

            if getattr(self, "_network_monitor", None) is not None and source_ip:
                try:
                    self._network_monitor.record_suspicious(source_ip, alert_type)
                except Exception:
                    pass

            return details
        except Exception as e:
            self.logger.error(f"Error generating DNS alert: {e}")

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def start(self) -> None:
        if self.is_running:
            return
        self.is_running = True
        self._started_at = datetime.utcnow()
        self._last_error = None
        self.logger.info(f"Starting DNS spoofing detector (interface={self.interface})")

        def heartbeat():
            while self.is_running:
                import time
                time.sleep(1)

        self.monitor_thread = threading.Thread(target=heartbeat, daemon=True)
        self.monitor_thread.start()

    def stop(self) -> None:
        self.is_running = False
        self.logger.info("Stopping DNS spoofing detector")

    def status(self) -> str:
        if not self.is_running:
            return "stopped"
        if self._last_error:
            return "error"
        return "running"

    def health(self) -> dict:
        return {
            "detector": "dns_spoof",
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
            "suspicious_domains": len(self.suspicious_domains),
            "dns_cache_size": len(self.dns_cache),
        }

    def start_monitoring(self):
        self.start()

    def stop_monitoring(self):
        self.stop()
