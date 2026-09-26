"""Focused, offline tests for persistence and path invariants."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))

from utils.config import Config
from utils.database import DatabaseManager
from utils.paths import BACKEND_ROOT, CONFIG_PATH


class PersistenceContractsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.db = DatabaseManager(Path(self.tempdir.name) / "test.db")

    def tearDown(self) -> None:
        self.tempdir.cleanup()

    def test_alert_type_round_trips_in_dedicated_column(self) -> None:
        alert_id = self.db.insert_alert(
            "arp_spoof", "high", "ARP mapping conflict", source_ip="192.0.2.10",
            alert_type="ip_mac_conflict", details={"alert_type": "ip_mac_conflict"},
        )
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT alert_type FROM alerts WHERE id = ?", (alert_id,)).fetchone()
        self.assertEqual(row["alert_type"], "ip_mac_conflict")

    def test_risk_score_is_persisted_for_insert_and_update(self) -> None:
        self.db.upsert_device("192.0.2.15", risk_score=25)
        self.db.upsert_device("192.0.2.15", risk_score=60)
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT risk_score FROM devices WHERE ip_address = ?", ("192.0.2.15",)).fetchone()
        self.assertEqual(row["risk_score"], 60)

    def test_default_config_path_is_backend_relative(self) -> None:
        config = Config()
        self.assertEqual(config.config_file, CONFIG_PATH)
        self.assertEqual(config.database_path(), BACKEND_ROOT / "shadowpulse.db")


if __name__ == "__main__":
    unittest.main()
