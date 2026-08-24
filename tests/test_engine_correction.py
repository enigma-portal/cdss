"""Regression coverage for deterministic CDSS engine correction."""

from pathlib import Path
import tempfile
import unittest

import app.database as database
from app.database.seed import seed_knowledge_base
from app.risk_engine.scoring import calculate_risk
from app.routes.auth import _validated_siem_endpoint
from app.services.alert_parser import parse_alert
from app.services.classification import classify
from app.services.incident_processor import process_alert
from app.services.poller import start_realtime_poller
from app.services.recommendation_engine import rebuild_recommendations
from app.services.recommendation_engine import generate_recommendations


def alert(identifier="a-1", level=8, mitre=None, groups=None):
    rule = {"id": "5710", "level": level, "description": "Security event"}
    if mitre is not None:
        rule["mitre"] = {"id": mitre}
    if groups is not None:
        rule["groups"] = groups
    return {"id": identifier, "timestamp": "2026-08-24T10:00:00+00:00", "rule": rule,
            "agent": {"id": "001", "name": "host-1"},
            "data": {"srcip": "192.0.2.10", "srcuser": "alice"}}


class EngineCorrectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_database = database.DATABASE
        database.DATABASE = Path(self.temp.name) / "test.db"
        seed_knowledge_base()

    def tearDown(self):
        database.DATABASE = self.original_database
        self.temp.cleanup()

    def test_parser_preserves_multiple_valid_unique_mitre_ids(self):
        parsed = parse_alert(alert(mitre=["T1110", "t1059.001", "T1110", "invalid"]))
        self.assertEqual(parsed.mitre_ids, ("T1110", "T1059.001"))

    def test_parser_handles_missing_optional_context(self):
        parsed = parse_alert({"timestamp": "2026-08-24T10:00:00Z",
                              "rule": {"id": "1", "level": 1}})
        self.assertIsNone(parsed.source_ip)
        self.assertIsNone(parsed.username)
        self.assertEqual(parsed.rule_groups, ())

    def test_parser_rejects_malformed_external_fields(self):
        with self.assertRaises(ValueError):
            parse_alert(alert(groups="authentication_failed"))
        bad_ip = alert()
        bad_ip["data"]["srcip"] = "not-an-ip"
        with self.assertRaises(ValueError):
            parse_alert(bad_ip)

    def test_classification_precedence_and_fallbacks(self):
        mapped = classify(("T1110",), ("authentication_failed", "sshd"))
        self.assertEqual(mapped["source"], "MITRE")
        self.assertIn("Authentication Failure", mapped["context"])
        fallback = classify((), ("authentication_failed",))
        self.assertEqual((fallback["source"], fallback["label"]),
                         ("WAZUH_GROUP", "Authentication Failure"))
        unknown = classify((), ("unverified_group",))
        self.assertEqual(unknown["source"], "UNCLASSIFIED")

    def test_risk_has_distinct_mapped_and_wazuh_only_paths(self):
        mapped = calculate_risk(8, 9, 1)
        unmapped = calculate_risk(8, None, 1)
        self.assertEqual(mapped.risk_basis, "WAZUH_PLUS_MITRE")
        self.assertEqual(unmapped.risk_basis, "WAZUH_ONLY")
        self.assertEqual(unmapped.technique_risk_score, 0)
        self.assertGreaterEqual(unmapped.final_risk_score, 0)
        self.assertLessEqual(unmapped.final_risk_score, 10)

    def test_multiple_mitre_ids_and_explainability_are_persisted(self):
        result = process_alert(alert(mitre=["T1110", "T1059.001"],
                                     groups=["authentication_failed", "sshd"]))
        connection = database.get_db_connection()
        try:
            incident = connection.execute("SELECT * FROM incidents WHERE id = ?",
                                          (result["incident_id"],)).fetchone()
            techniques = connection.execute("""
                SELECT technique_id FROM incident_mitre_techniques
                WHERE incident_id = ? ORDER BY ordinal
            """, (result["incident_id"],)).fetchall()
        finally:
            connection.close()
        self.assertEqual([row[0] for row in techniques], ["T1110", "T1059.001"])
        self.assertEqual(incident["classification_source"], "MITRE")
        self.assertEqual(incident["risk_basis"], "WAZUH_PLUS_MITRE")

    def test_duplicate_alert_and_mitre_mapping_are_prevented(self):
        first = process_alert(alert(mitre=["T1110", "T1110"]))
        second = process_alert(alert(mitre=["T1110", "T1110"]))
        self.assertTrue(first["created"])
        self.assertFalse(second["created"])
        connection = database.get_db_connection()
        try:
            count = connection.execute("SELECT COUNT(*) FROM incident_mitre_techniques").fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(count, 1)

    def test_unknown_event_stays_unclassified_with_conservative_guidance(self):
        result = process_alert(alert(mitre=None, groups=["unknown_group"]))
        connection = database.get_db_connection()
        try:
            incident = connection.execute("SELECT * FROM incidents WHERE id = ?",
                                          (result["incident_id"],)).fetchone()
        finally:
            connection.close()
        self.assertEqual(incident["classification_source"], "UNCLASSIFIED")
        self.assertEqual(incident["risk_basis"], "WAZUH_ONLY")
        self.assertIn("Review the original", result["recommendations"][0]["action_text"])

    def test_recommendation_rebuild_is_deterministic(self):
        result = process_alert(alert(mitre=["T1110"], groups=["authentication_failed"]))
        connection = database.get_db_connection()
        try:
            before = [tuple(row) for row in connection.execute("""
                SELECT action_text, response_phase, priority, framework, control_reference, rationale
                FROM incident_recommendations WHERE incident_id = ? ORDER BY priority, id
            """, (result["incident_id"],)).fetchall()]
            with connection:
                rebuild_recommendations(connection)
            after = [tuple(row) for row in connection.execute("""
                SELECT action_text, response_phase, priority, framework, control_reference, rationale
                FROM incident_recommendations WHERE incident_id = ? ORDER BY priority, id
            """, (result["incident_id"],)).fetchall()]
        finally:
            connection.close()
        self.assertEqual(before, after)

    def test_same_technique_changes_recommendation_strength_with_risk(self):
        connection = database.get_db_connection()
        try:
            low = generate_recommendations(connection, ("T1110",), 2.0)
            high = generate_recommendations(connection, ("T1110",), 7.0)
        finally:
            connection.close()
        self.assertTrue(low)
        self.assertNotEqual([item["action_text"] for item in low],
                            [item["action_text"] for item in high])
        self.assertTrue(any("Containment" in item["response_phase"] for item in high))

    def test_knowledge_provenance_is_explicit(self):
        connection = database.get_db_connection()
        try:
            row = connection.execute("""
                SELECT mapping_type, verified_status FROM knowledge_provenance LIMIT 1
            """).fetchone()
        finally:
            connection.close()
        self.assertEqual((row["mapping_type"], row["verified_status"]), ("project_defined", 0))

    def test_realtime_disabled_does_not_start_thread(self):
        self.assertIsNone(start_realtime_poller(False))

    def test_ssrf_rejects_loopback_and_non_https(self):
        with self.assertRaises(ValueError):
            _validated_siem_endpoint("http://192.0.2.10", "9200")
        with self.assertRaises(ValueError):
            _validated_siem_endpoint("https://127.0.0.1", "9200", resolve=True)


if __name__ == "__main__":
    unittest.main()
