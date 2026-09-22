import re
import json
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple, Union
from dataclasses import dataclass
from ipaddress import IPv4Address, AddressValueError
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dns import DNS
from scapy.layers.http import HTTP

@dataclass
class ParsedPacket:
    """Structured representation of a parsed packet"""
    timestamp: datetime
    source_ip: str
    dest_ip: str
    source_port: Optional[int]
    dest_port: Optional[int]
    protocol: str
    packet_size: int
    flags: List[str]
    payload_hash: str
    payload_snippet: str
    session_id: str
    packet_type: str
    suspicious_indicators: List[str]

class PacketAnalyzer:
    """Advanced packet analysis and threat detection"""
    
    def __init__(self):
        self.suspicious_patterns = self._load_suspicious_patterns()
        self.session_tracker = {}
        self.dns_cache = {}
        
    def _load_suspicious_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for detecting suspicious activity"""
        return {
            'sql_injection': [
                r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table",
                r"insert\s+into", r"delete\s+from", r"update\s+.*\s+set"
            ],
            'xss_patterns': [
                r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
                r"eval\s*\(", r"document\.cookie"
            ],
            'directory_traversal': [
                r"\.\.\/", r"\.\.\\", r"%2e%2e%2f", r"%2e%2e%5c"
            ],
            'command_injection': [
                r";\s*cat\s+", r";\s*ls\s+", r";\s*pwd", r";\s*whoami",
                r"\|\s*nc\s+", r"&&\s*wget", r"\$\(.*\)"
            ],
            'malware_domains': [
                r".*\.tk$", r".*\.ml$", r".*suspicious-domain\.com",
                r"malware\..*", r"botnet\..*"
            ]
        }
    
    def parse_packet(self, packet: scapy.Packet) -> Optional[ParsedPacket]:
        """Parse a scapy packet into structured format"""
        try:
            if not packet.haslayer(IP):
                return None
            
            ip_layer = packet[IP]
            timestamp = datetime.now()
            
            # Basic packet info
            source_ip = ip_layer.src
            dest_ip = ip_layer.dst
            packet_size = len(packet)
            protocol = self._get_protocol_name(packet)
            
            # Port information
            source_port = None
            dest_port = None
            flags = []
            
            if packet.haslayer(TCP):
                tcp_layer = packet[TCP]
                source_port = tcp_layer.sport
                dest_port = tcp_layer.dport
                flags = self._parse_tcp_flags(tcp_layer.flags)
            elif packet.haslayer(UDP):
                udp_layer = packet[UDP]
                source_port = udp_layer.sport
                dest_port = udp_layer.dport
            
            # Payload analysis
            payload = self._extract_payload(packet)
            payload_hash = hashlib.md5(payload).hexdigest() if payload else ""
            payload_snippet = payload[:200].decode('utf-8', errors='ignore') if payload else ""
            
            # Session tracking
            session_id = self._generate_session_id(source_ip, dest_ip, source_port, dest_port, protocol)
            
            # Packet classification
            packet_type = self._classify_packet(packet)
            
            # Threat detection
            suspicious_indicators = self._detect_threats(packet, payload_snippet)
            
            return ParsedPacket(
                timestamp=timestamp,
                source_ip=source_ip,
                dest_ip=dest_ip,
                source_port=source_port,
                dest_port=dest_port,
                protocol=protocol,
                packet_size=packet_size,
                flags=flags,
                payload_hash=payload_hash,
                payload_snippet=payload_snippet,
                session_id=session_id,
                packet_type=packet_type,
                suspicious_indicators=suspicious_indicators
            )
            
        except Exception as e:
            print(f"Packet parsing error: {e}")
            return None
    
    def _get_protocol_name(self, packet: scapy.Packet) -> str:
        """Get protocol name from packet"""
        if packet.haslayer(TCP):
            return 'TCP'
        elif packet.haslayer(UDP):
            return 'UDP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        elif packet.haslayer(ARP):
            return 'ARP'
        else:
            return 'OTHER'
    
    def _parse_tcp_flags(self, flags: int) -> List[str]:
        """Parse TCP flags"""
        flag_names = []
        flag_mapping = {
            0x01: 'FIN', 0x02: 'SYN', 0x04: 'RST', 0x08: 'PSH',
            0x10: 'ACK', 0x20: 'URG', 0x40: 'ECE', 0x80: 'CWR'
        }
        
        for flag_bit, flag_name in flag_mapping.items():
            if flags & flag_bit:
                flag_names.append(flag_name)
        
        return flag_names
    
    def _extract_payload(self, packet: scapy.Packet) -> bytes:
        """Extract packet payload"""
        try:
            if packet.haslayer(scapy.Raw):
                return bytes(packet[scapy.Raw])
            elif packet.haslayer(TCP) and len(packet[TCP].payload) > 0:
                return bytes(packet[TCP].payload)
            elif packet.haslayer(UDP) and len(packet[UDP].payload) > 0:
                return bytes(packet[UDP].payload)
        except Exception:
            pass
        return b""
    
    def _generate_session_id(self, src_ip: str, dst_ip: str, src_port: int, 
                           dst_port: int, protocol: str) -> str:
        """Generate unique session ID"""
        session_data = f"{src_ip}:{src_port}->{dst_ip}:{dst_port}:{protocol}"
        return hashlib.md5(session_data.encode()).hexdigest()[:16]
    
    def _classify_packet(self, packet: scapy.Packet) -> str:
        """Classify packet type"""
        if packet.haslayer(DNS):
            return 'DNS'
        elif packet.haslayer(HTTP):
            return 'HTTP'
        elif packet.haslayer(ARP):
            return 'ARP'
        elif packet.haslayer(ICMP):
            return 'ICMP'
        elif packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            if tcp_layer.dport in [80, 8080]:
                return 'HTTP'
            elif tcp_layer.dport in [443, 8443]:
                return 'HTTPS'
            elif tcp_layer.dport == 22:
                return 'SSH'
            elif tcp_layer.dport == 21:
                return 'FTP'
            elif tcp_layer.dport == 25:
                return 'SMTP'
            else:
                return 'TCP'
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            if udp_layer.dport == 53:
                return 'DNS'
            elif udp_layer.dport == 67 or udp_layer.dport == 68:
                return 'DHCP'
            else:
                return 'UDP'
        else:
            return 'UNKNOWN'
    
    def _detect_threats(self, packet: scapy.Packet, payload: str) -> List[str]:
        """Detect potential threats in packet"""
        indicators = []
        
        # Payload-based detection
        for threat_type, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if re.search(pattern, payload, re.IGNORECASE):
                    indicators.append(f"{threat_type}:{pattern}")
        
        # Network-based detection
        if packet.haslayer(IP):
            ip_layer = packet[IP]
            
            # Private IP in public communication
            if self._is_private_ip(ip_layer.src) and not self._is_private_ip(ip_layer.dst):
                indicators.append("private_to_public_communication")
            
            # Unusual packet size
            if len(packet) > 9000:  # Jumbo frame
                indicators.append("jumbo_packet")
            elif len(packet) < 64:  # Tiny packet
                indicators.append("tiny_packet")
        
        # Protocol-specific detection
        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            
            # SYN flood detection
            if tcp_layer.flags == 2:  # SYN only
                indicators.append("potential_syn_flood")
            
            # Port scan detection
            if tcp_layer.dport > 65000:
                indicators.append("high_port_access")
        
        # DNS-specific detection
        if packet.haslayer(DNS):
            dns_layer = packet[DNS]
            if dns_layer.qd:
                query_name = dns_layer.qd.qname.decode('utf-8', errors='ignore')
                if len(query_name) > 100:
                    indicators.append("dns_long_query")
                if re.search(r"[0-9a-f]{32,}", query_name):
                    indicators.append("dns_suspicious_query")
        
        return indicators
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP address is private"""
        try:
            addr = IPv4Address(ip)
            return addr.is_private
        except AddressValueError:
            return False

class LogParser:
    """Parse various log formats and extract security events"""
    
    def __init__(self):
        self.packet_analyzer = PacketAnalyzer()
        self.log_patterns = self._load_log_patterns()
    
    def _load_log_patterns(self) -> Dict[str, Dict[str, str]]:
        """Load regex patterns for different log formats"""
        return {
            'apache_access': {
                'pattern': r'(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<version>[^"]*)" (?P<status>\d+) (?P<size>\S+)',
                'timestamp_format': '%d/%b/%Y:%H:%M:%S %z'
            },
            'nginx_access': {
                'pattern': r'(?P<ip>\S+) - \S+ \[(?P<timestamp>[^\]]+)\] "(?P<method>\S+) (?P<url>\S+) (?P<version>[^"]*)" (?P<status>\d+) (?P<size>\d+) "(?P<referer>[^"]*)" "(?P<user_agent>[^"]*)"',
                'timestamp_format': '%d/%b/%Y:%H:%M:%S %z'
            },
            'syslog': {
                'pattern': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) (?P<process>\S+): (?P<message>.*)',
                'timestamp_format': '%b %d %H:%M:%S'
            },
            'iptables': {
                'pattern': r'(?P<timestamp>\w+\s+\d+\s+\d+:\d+:\d+) (?P<hostname>\S+) kernel: (?P<message>.*)',
                'timestamp_format': '%b %d %H:%M:%S'
            }
        }
    
    def parse_log_line(self, log_line: str, log_type: str = 'auto') -> Optional[Dict[str, Any]]:
        """Parse a single log line"""
        if log_type == 'auto':
            log_type = self._detect_log_type(log_line)
        
        if log_type not in self.log_patterns:
            return None
        
        pattern = self.log_patterns[log_type]['pattern']
        timestamp_format = self.log_patterns[log_type]['timestamp_format']
        
        match = re.match(pattern, log_line)
        if not match:
            return None
        
        parsed_data = match.groupdict()
        
        # Parse timestamp
        try:
            if 'timestamp' in parsed_data:
                if timestamp_format == '%b %d %H:%M:%S':
                    # Add current year for syslog format
                    timestamp_str = f"{datetime.now().year} {parsed_data['timestamp']}"
                    parsed_data['timestamp'] = datetime.strptime(timestamp_str, f'%Y {timestamp_format}')
                else:
                    parsed_data['timestamp'] = datetime.strptime(parsed_data['timestamp'], timestamp_format)
        except ValueError:
            parsed_data['timestamp'] = datetime.now()
        
        # Add log type
        parsed_data['log_type'] = log_type
        
        # Extract security indicators
        parsed_data['security_indicators'] = self._analyze_log_security(parsed_data, log_type)
        
        return parsed_data
    
    def _detect_log_type(self, log_line: str) -> str:
        """Auto-detect log format type"""
        # Apache/Nginx access log detection
        if re.search(r'\d+\.\d+\.\d+\.\d+ .* \[.*\] ".*" \d+ \d+', log_line):
            if '"' in log_line and log_line.count('"') >= 6:
                return 'nginx_access'
            else:
                return 'apache_access'
        
        # Syslog detection
        if re.search(r'\w+\s+\d+\s+\d+:\d+:\d+ \S+ \S+:', log_line):
            if 'kernel:' in log_line and ('DROP' in log_line or 'REJECT' in log_line):
                return 'iptables'
            else:
                return 'syslog'
        
        return 'unknown'
    
    def _analyze_log_security(self, parsed_data: Dict[str, Any], log_type: str) -> List[str]:
        """Analyze log entry for security indicators"""
        indicators = []
        
        if log_type in ['apache_access', 'nginx_access']:
            # Web-specific security analysis
            url = parsed_data.get('url', '')
            status = int(parsed_data.get('status', 0))
            user_agent = parsed_data.get('user_agent', '')
            
            # SQL injection patterns
            if re.search(r"(union|select|insert|delete|update|drop|create|alter)", url, re.IGNORECASE):
                indicators.append('sql_injection_attempt')
            
            # XSS patterns
            if re.search(r"(<script|javascript:|onerror|onload)", url, re.IGNORECASE):
                indicators.append('xss_attempt')
            
            # Directory traversal
            if re.search(r"(\.\./|\.\.\\|%2e%2e)", url, re.IGNORECASE):
                indicators.append('directory_traversal')
            
            # Error status codes
            if status >= 400:
                indicators.append(f'http_error_{status}')
            
            # Suspicious user agents
            if re.search(r"(sqlmap|nikto|nmap|masscan|zap)", user_agent, re.IGNORECASE):
                indicators.append('scanner_user_agent')
            
            # Empty or suspicious user agent
            if not user_agent or user_agent == '-':
                indicators.append('empty_user_agent')
        
        elif log_type == 'iptables':
            # Firewall log analysis
            message = parsed_data.get('message', '')
            
            if 'DROP' in message:
                indicators.append('firewall_drop')
            if 'REJECT' in message:
                indicators.append('firewall_reject')
            
            # Extract IPs from ipt# utils/__init__.py