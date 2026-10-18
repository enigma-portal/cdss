"""Phase 2 normalization, lifecycle, cursor, and polling safety tests."""

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import app.database as database
from app.database import get_db_connection, initialize_database
from app.services.alert_parser import parse_alert
from app.services.incident_processor import process_alert
from app.services.poller import _poll_once


def event(identifier="event-1", agent="001", mitre=None):
    rule = {"id": "5710", "description": "Authentication event", "level": 5,
            "groups": ["authentication"]}
    if mitre is not None:
        rule["mitre"] = {"id": mitre}
    return {"id": identifier, "timestamp": "2026-09-20T10:00:00Z", "rule": rule,
            "agent": {"id": agent, "name": "host"}, "data": {"srcuser": "alice"}}


class PhaseTwoIngestionTests(unittest.TestCase):
    def setUp(self):
        self.original = database.DATABASE
        self.directory = tempfile.TemporaryDirectory()
        database.DATABASE = Path(self.directory.name) / "phase2.db"
        initialize_database()

    def tearDown(self):
        database.DATABASE = self.original
        self.directory.cleanup()

    def add_connector(self, enabled=True):
        connection = get_db_connection()
        with connection:
            result = connection.execute("""INSERT INTO siem_connections
                (name,connector_type,base_url,port,index_pattern,username,encrypted_password,verify_tls,is_enabled)
                VALUES('test','wazuh_indexer','https://siem.example',9200,'wazuh-alerts-*','reader',X'01',1,?)""",
                (int(enabled),))
        connection.close()
        return result.lastrowid

    def test_normalization_optional_fields_raw_json_and_multiple_mitre(self):
        source = event(mitre=["T1110", "T1059.001", "T1110"])
        source["data"] = {}
        parsed = parse_alert(source)
        self.assertIsNone(parsed.source_ip); self.assertIsNone(parsed.destination_ip)
        self.assertIsNone(parsed.username)
        self.assertEqual(json.loads(parsed.raw_alert), source)
        result = process_alert(source)
        connection = get_db_connection()
        row = connection.execute("SELECT * FROM alerts WHERE wazuh_alert_id='event-1'").fetchone()
        connection.close()
        self.assertTrue(result["created"])
        self.assertEqual(json.loads(row["wazuh_mitre_ids"]), ["T1110", "T1059.001"])
        self.assertEqual(row["mitre_id"], "T1110")
        self.assertEqual(json.loads(row["raw_alert"]), source)

    def test_duplicate_and_processed_lifecycle(self):
        first = process_alert(event()); second = process_alert(event())
        connection = get_db_connection()
        counts = connection.execute("SELECT (SELECT COUNT(*) FROM alerts),(SELECT COUNT(*) FROM incidents)").fetchone()
        status = connection.execute("SELECT processing_status FROM alerts").fetchone()[0]
        connection.close()
        self.assertTrue(first["created"]); self.assertFalse(second["created"])
        self.assertEqual(tuple(counts), (1, 1)); self.assertEqual(status, "processed")

    def test_downstream_failure_marks_failed_and_safe_retry(self):
        with patch("app.services.incident_processor.generate_recommendations",
                   side_effect=RuntimeError("downstream unavailable")):
            with self.assertRaises(RuntimeError):
                process_alert(event())
        connection = get_db_connection()
        self.assertEqual(connection.execute("SELECT processing_status FROM alerts").fetchone()[0], "failed")
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 0)
        connection.close()
        result = process_alert(event())
        self.assertTrue(result["created"])
        connection = get_db_connection()
        self.assertEqual(connection.execute("SELECT processing_status FROM alerts").fetchone()[0], "processed")
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], 1)
        connection.close()

    def test_historical_status_backfill_uses_linked_incident_only(self):
        process_alert(event())
        connection = get_db_connection()
        with connection:
            connection.execute("UPDATE alerts SET processing_status='new'")
            before = connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
        connection.close(); initialize_database(); connection = get_db_connection()
        self.assertEqual(connection.execute("SELECT processing_status FROM alerts").fetchone()[0], "processed")
        self.assertEqual(connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0], before)
        connection.close()

    def test_exact_asset_resolution_and_unmatched_null(self):
        connection = get_db_connection()
        with connection:
            asset_id = connection.execute("""INSERT INTO assets
              (asset_name,asset_type,asset_role,os_family,os_name,wazuh_agent_id,criticality,is_protected)
              VALUES('host','Other','Other','N/A','N/A','001','medium',1)""").lastrowid
        connection.close()
        process_alert(event("mapped", "001")); process_alert(event("unmatched", "002"))
        connection = get_db_connection()
        rows = connection.execute("SELECT wazuh_alert_id,asset_id FROM alerts ORDER BY id").fetchall(); connection.close()
        self.assertEqual(rows[0]["asset_id"], asset_id); self.assertIsNone(rows[1]["asset_id"])

    def test_disabled_connector_is_not_polled(self):
        self.add_connector(enabled=False)
        with patch("app.services.poller.create_connector") as factory:
            _poll_once(10, 0)
        factory.assert_not_called()

    def test_cursor_resume_and_malformed_batch_does_not_advance(self):
        connector_id = self.add_connector()
        class Connector:
            calls = []
            def fetch_event_page(self, *, size, search_after=None):
                self.calls.append(search_after)
                return [event()], ("2026-09-20T10:00:00Z", "doc-a")
        connector = Connector()
        with patch("app.services.poller.unprotect_secret", return_value="secret"), \
             patch("app.services.poller.create_connector", return_value=connector):
            _poll_once(10, 0); _poll_once(10, 0)
        self.assertEqual(connector.calls, [None, ["2026-09-20T10:00:00Z", "doc-a"]])
        connection = get_db_connection()
        cursor = connection.execute("SELECT event_timestamp,document_id FROM ingestion_cursors WHERE connection_id=?", (connector_id,)).fetchone()
        connection.close(); self.assertEqual(tuple(cursor), ("2026-09-20T10:00:00Z", "doc-a"))

        class Malformed:
            def fetch_event_page(self, **kwargs):
                return [{"id": "bad", "timestamp": "2026-09-20T10:01:00Z", "rule": "invalid"}], ("later", "doc-b")
        with patch("app.services.poller.unprotect_secret", return_value="secret"), \
             patch("app.services.poller.create_connector", return_value=Malformed()):
            _poll_once(10, 0)
        connection = get_db_connection()
        cursor = connection.execute("SELECT event_timestamp,document_id FROM ingestion_cursors WHERE connection_id=?", (connector_id,)).fetchone()
        connection.close(); self.assertEqual(tuple(cursor), ("2026-09-20T10:00:00Z", "doc-a"))

    def test_unexpected_errors_do_not_expose_secrets(self):
        connector_id = self.add_connector()
        class Broken:
            def fetch_event_page(self, **kwargs):
                raise RuntimeError("password=super-secret")
        with patch("app.services.poller.unprotect_secret", return_value="secret"), \
             patch("app.services.poller.create_connector", return_value=Broken()):
            _poll_once(10, 0)
        connection = get_db_connection()
        message = connection.execute("SELECT last_error FROM siem_connections WHERE id=?", (connector_id,)).fetchone()[0]
        connection.close()
        self.assertNotIn("super-secret", message); self.assertIn("Unexpected", message)

    def test_malformed_required_fields_rejected_but_optional_absence_allowed(self):
        parsed = parse_alert({"id":"partial","timestamp":"2026-09-20T10:00:00Z","rule":{"id":"1"}})
        self.assertIsNone(parsed.rule_level); self.assertEqual(parsed.mitre_ids, ())
        with self.assertRaises(ValueError):
            process_alert({"timestamp":"2026-09-20T10:00:00Z","rule":{"id":"1"}})
        with self.assertRaises(ValueError):
            parse_alert({"id":"bad","timestamp":"not-a-date","rule":{"id":"1"}})


if __name__ == "__main__":
    unittest.main()
