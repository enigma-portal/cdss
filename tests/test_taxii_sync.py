"""Tests for mapping ATT&CK STIX objects into the CDSS schema."""

import unittest

from app.mitre.taxii_sync import extract_techniques


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


if __name__ == "__main__":
    unittest.main()
