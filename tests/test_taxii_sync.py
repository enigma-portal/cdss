"""Tests for mapping ATT&CK STIX objects into the CDSS schema."""

import unittest
from pathlib import Path
import tempfile
from unittest.mock import Mock

import app.database as database
from app.database.seed import seed_knowledge_base
from app.mitre.taxii_sync import extract_techniques, sync_enterprise_attack
from app.services.incident_processor import process_alert


def stix_technique(technique_id="T1110", name="Brute Force", tactics=()):
    return {
        "type": "attack-pattern", "name": name, "description": "Catalogue fixture",
        "x_mitre_domains": ["enterprise-attack"],
        "external_references": [{"source_name": "mitre-attack", "external_id": technique_id}],
        "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": tactic}
                              for tactic in tactics],
    }


class TaxiiSyncTests(unittest.TestCase):
    def test_extracts_active_enterprise_technique(self):
        objects = [{
            "type": "attack-pattern",
            "name": "Brute Force",
            "description": "Test description",
            "x_mitre_domains": ["enterprise-attack"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T1110"}],
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "credential-access"}],
        }, {
            "type": "attack-pattern",
            "name": "Old technique",
            "revoked": True,
            "x_mitre_domains": ["enterprise-attack"],
            "external_references": [{"source_name": "mitre-attack", "external_id": "T0000"}],
        }]

        techniques = extract_techniques(objects)

        self.assertEqual(techniques, [{
            "technique_id": "T1110",
            "technique_name": "Brute Force",
            "tactic": "Credential Access",
            "description": "Test description",
        }])

    def test_all_unique_tactics_are_retained_in_source_order(self):
        techniques = extract_techniques([stix_technique(
            tactics=("persistence", "defense-evasion", "persistence", "privilege-escalation"))])
        self.assertEqual(techniques[0]["tactic"],
                         "Persistence / Defense Evasion / Privilege Escalation")

    def test_invalid_ids_and_inactive_or_other_domain_objects_are_skipped(self):
        invalid = stix_technique("not-an-attack-id")
        mobile = stix_technique("T1110")
        mobile["x_mitre_domains"] = ["mobile-attack"]
        deprecated = stix_technique("T1059")
        deprecated["x_mitre_deprecated"] = True
        missing = stix_technique(None)
        result = extract_techniques([invalid, mobile, deprecated, missing,
                                     stix_technique("t1059.001")])
        self.assertEqual([item["technique_id"] for item in result], ["T1059.001"])

    def test_absent_tactics_are_unavailable(self):
        self.assertIsNone(extract_techniques([stix_technique()])[0]["tactic"])


class TaxiiCatalogueSyncTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original_database = database.DATABASE
        database.DATABASE = Path(self.temp.name) / "test.db"
        seed_knowledge_base()

    def tearDown(self):
        database.DATABASE = self.original_database
        self.temp.cleanup()

    def _sync(self, objects):
        client = Mock()
        client.fetch_enterprise_objects.return_value = objects
        return sync_enterprise_attack(client)

    def test_synced_catalogue_is_not_overwritten_by_later_seed(self):
        self.assertEqual(self._sync([stix_technique(
            "T1078", "Synced catalogue fixture", ("initial-access", "persistence"))]), 1)
        seed_knowledge_base()
        connection = database.get_db_connection()
        try:
            technique = connection.execute(
                "SELECT * FROM mitre_techniques WHERE technique_id = 'T1078'"
            ).fetchone()
            self.assertEqual(technique["technique_name"], "Synced catalogue fixture")
            self.assertEqual(technique["tactic"], "Initial Access / Persistence")
            self.assertEqual(technique["description"], "Catalogue fixture")
            self.assertEqual(technique["catalogue_source"], "taxii")
            self.assertIsNotNone(technique["catalogue_synced_at"])
            seeded = connection.execute(
                "SELECT catalogue_source FROM mitre_techniques WHERE technique_id = 'T1110'"
            ).fetchone()
            self.assertEqual(seeded[0], "project_seed")
        finally:
            connection.close()

    def test_placeholder_is_enriched_without_remapping_or_rescoring(self):
        result = process_alert({
            "id": "taxii-placeholder", "timestamp": "2026-09-21T10:00:00Z",
            "rule": {"id": "9010", "level": 8, "description": "Catalogue test event",
                     "mitre": {"id": ["T1550.001"]}},
        })
        tables = ("alerts", "incidents", "risk_scores", "knowledge_base",
                  "alert_mitre_techniques", "incident_mitre_techniques",
                  "incident_recommendations")
        connection = database.get_db_connection()
        try:
            before = {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                      for table in tables}
            risk_before = connection.execute(
                "SELECT risk_basis FROM incidents WHERE id = ?", (result["incident_id"],)
            ).fetchone()[0]
        finally:
            connection.close()
        self.assertEqual(risk_before, "WAZUH_ONLY")
        self.assertEqual(self._sync([stix_technique(
            "T1550.001", "Application Access Token", ("defense-evasion", "lateral-movement"))]), 1)
        connection = database.get_db_connection()
        try:
            after = {table: [tuple(row) for row in connection.execute(f"SELECT * FROM {table}")]
                     for table in tables}
            self.assertEqual(after, before)
            technique = connection.execute(
                "SELECT * FROM mitre_techniques WHERE technique_id = 'T1550.001'"
            ).fetchone()
            self.assertEqual(technique["technique_name"], "Application Access Token")
            self.assertEqual(technique["catalogue_source"], "taxii")
            self.assertEqual(technique["tactic"], "Defense Evasion / Lateral Movement")
            self.assertEqual(connection.execute("PRAGMA foreign_key_check").fetchall(), [])
        finally:
            connection.close()


class OfficialStixBootstrapTests(TaxiiCatalogueSyncTests):
    def test_local_bundle_import_records_transport_and_hash(self):
        import json
        import hashlib
        from app.mitre.taxii_sync import OfficialStixClient
        path = Path(self.temp.name) / 'enterprise.json'
        payload = json.dumps({'type':'bundle', 'objects':[
            stix_technique('T1110', 'Official fixture', ('credential-access','discovery'))]}).encode()
        path.write_bytes(payload)
        self.assertEqual(sync_enterprise_attack(OfficialStixClient(path)), 1)
        connection = database.get_db_connection()
        try:
            row = connection.execute('SELECT * FROM attack_catalogue_imports').fetchone()
            self.assertEqual(row['transport'], 'local_stix')
            self.assertEqual(row['sha256'], hashlib.sha256(payload).hexdigest())
            self.assertEqual(connection.execute("SELECT tactic FROM mitre_techniques WHERE technique_id='T1110'").fetchone()[0], 'Credential Access / Discovery')
        finally:
            connection.close()

    def test_taxii_failure_uses_official_bundle(self):
        from unittest.mock import patch
        from app.mitre.taxii_sync import OfficialStixClient, TaxiiSyncError
        with patch('app.mitre.taxii_sync.AttackTaxiiClient.fetch_enterprise_objects', side_effect=TaxiiSyncError('offline')), patch.object(OfficialStixClient, 'fetch_enterprise_objects', return_value=[stix_technique()]):
            self.assertEqual(sync_enterprise_attack(), 1)

    def test_invalid_bundle_does_not_modify_catalogue(self):
        from app.mitre.taxii_sync import OfficialStixClient, TaxiiSyncError
        path = Path(self.temp.name) / 'invalid.json'
        path.write_text('{"type":"bundle","objects":[]}', encoding='utf-8')
        with self.assertRaises(TaxiiSyncError):
            sync_enterprise_attack(OfficialStixClient(path))

    def test_official_tactic_names_retained(self):
        objects = [stix_technique(tactics=('credential-access','discovery')),
                   {'type':'x-mitre-tactic','x_mitre_shortname':'credential-access','name':'Credential Access'},
                   {'type':'x-mitre-tactic','x_mitre_shortname':'discovery','name':'Discovery'}]
        self.assertEqual(extract_techniques(objects)[0]['tactic'], 'Credential Access / Discovery')


if __name__ == "__main__":
    unittest.main()
