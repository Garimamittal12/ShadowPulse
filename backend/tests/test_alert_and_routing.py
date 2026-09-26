"""Offline tests for alert lifecycle and dispatcher protocol routing."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from core import alert_manager as alert_module
from core.packet_dispatcher import PacketDispatcher
from utils.database import DatabaseManager


class Packet:
    def __init__(self, *layers: str):
        self.layers = set(layers)

    def haslayer(self, layer) -> bool:
        return layer in self.layers


class AlertAndRoutingTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.tempdir.name) / "alerts.db")
        self.original_factory = alert_module.get_db_manager
        alert_module.get_db_manager = lambda: self.db
        self.manager = alert_module.AlertManager(cooldown_seconds=60)

    def tearDown(self) -> None:
        alert_module.get_db_manager = self.original_factory
        self.tempdir.cleanup()

    def test_alert_type_is_durable_and_duplicates_are_suppressed(self) -> None:
        first = self.manager.raise_alert(
            detector="dns_spoof", alert_type="dns_response_conflict", severity="high",
            source_ip="203.0.113.53", target_ip="192.0.2.20",
        )
        duplicate = self.manager.raise_alert(
            detector="dns_spoof", alert_type="dns_response_conflict", severity="high",
            source_ip="203.0.113.53", target_ip="192.0.2.20",
        )
        self.assertIsNotNone(first)
        self.assertIsNone(duplicate)
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT alert_type FROM alerts").fetchone()
        self.assertEqual(row["alert_type"], "dns_response_conflict")

    def test_dns_and_ssl_evidence_for_one_client_creates_incident(self) -> None:
        self.manager.raise_alert(
            detector="dns_spoof", alert_type="dns_response_conflict", severity="high",
            details={"client_ip": "192.0.2.21"}, source_ip="203.0.113.53",
        )
        self.manager.raise_alert(
            detector="ssl_strip", alert_type="https_to_http_downgrade", severity="high",
            details={"client_ip": "192.0.2.21"}, source_ip="192.0.2.21",
        )
        with self.db.get_connection() as conn:
            types = {row["alert_type"] for row in conn.execute("SELECT alert_type FROM alerts")}
        self.assertEqual(types, {"dns_response_conflict", "https_to_http_downgrade", "possible_mitm_chain"})

    def test_protocol_gates_match_detector_contract(self) -> None:
        self.assertTrue(PacketDispatcher._is_relevant_packet("network_monitor", Packet()))
        self.assertTrue(PacketDispatcher._is_relevant_packet("arp_spoof", Packet("ARP")))
        self.assertTrue(PacketDispatcher._is_relevant_packet("dhcp_spoofing", Packet("DHCP")))
        self.assertTrue(PacketDispatcher._is_relevant_packet("dns_spoof", Packet("DNS")))
        self.assertTrue(PacketDispatcher._is_relevant_packet("icmp_redirect", Packet("ICMP")))
        self.assertTrue(PacketDispatcher._is_relevant_packet("http_injection", Packet("TCP", "Raw")))
        self.assertTrue(PacketDispatcher._is_relevant_packet("ssl_strip", Packet("TCP", "Raw")))
        self.assertTrue(PacketDispatcher._is_relevant_packet("rogue_access", Packet("Dot11")))
        self.assertFalse(PacketDispatcher._is_relevant_packet("dns_spoof", Packet("TCP", "Raw")))


if __name__ == "__main__":
    unittest.main()
