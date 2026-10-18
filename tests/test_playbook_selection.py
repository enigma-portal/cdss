"""Synthetic Wazuh-style routing tests; no live SIEM or production test data."""

import json
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_alert_grouping as fixtures
from run import app
from app.database.archive_evidence import migrate_archive_evidence
from app.services.alert_view import group_context
from app.services.archive_evidence import start_group_archive_retrieval
from app.services.incident_processor import process_alert
from app.services.investigation import run_investigation, AUTH as LEGACY_AUTH, FALLBACK as LEGACY_FALLBACK
from app.services.playbook_registry import (
    AUTH, FILE_PROCESS, REMOTE_ACCESS, FALLBACK, PLAYBOOKS,
    evidence_status, select_playbook,
)


FIXTURES = json.loads((Path(__file__).parent / 'fixtures' / 'playbook_selection.json').read_text(
    encoding='utf-8'))


class PlaybookSelectionTests(unittest.TestCase):
    setUp = fixtures.AlertGroupingTests.setUp
    tearDown = fixtures.AlertGroupingTests.tearDown
    client = fixtures.AlertGroupingTests.client

    def ingest(self, scenario):
        ids = []
        for event in FIXTURES[scenario]:
            process_alert(event)
            ids.append(self.db.execute('SELECT id FROM alerts WHERE wazuh_alert_id=?',
                                       (event['id'],)).fetchone()[0])
        return ids

    def retrieve_without_network(self, alert_id):
        with self.db:
            self.db.execute('''INSERT INTO siem_connections
                (name,connector_type,base_url,port,index_pattern,username,
                 encrypted_password,verify_tls,is_enabled,status)
                VALUES('fixture','wazuh_indexer','https://fixture.invalid',9200,
                       'wazuh-alerts-*','reader',X'01',1,1,'connected')''')
        fake = Mock()
        fake.field_capabilities.return_value = {
            'indices': ['wazuh-archives-fixture'],
            'fields': {'timestamp': {'date': {'searchable': True, 'aggregatable': True}},
                       'agent.id': {'keyword': {'searchable': True, 'aggregatable': True}}},
        }
        fake.search_documents.return_value = {
            '_shards': {'failed': 0},
            'hits': {'total': {'value': 0, 'relation': 'eq'}, 'hits': []},
        }
        with (patch('app.services.archive_evidence.create_connector',
                    return_value=Mock(client=fake)),
              patch('app.services.archive_evidence.unprotect_secret', return_value='fixture-secret')):
            with app.app_context():
                execution = start_group_archive_retrieval(alert_id)
        return execution, fake

    def test_registry_provenance_and_evidence_contract(self):
        self.assertTrue(FIXTURES['synthetic_test_data'])
        self.assertEqual(set(PLAYBOOKS), {AUTH, FILE_PROCESS, REMOTE_ACCESS, FALLBACK})
        for key, definition in PLAYBOOKS.items():
            with self.subTest(key=key):
                self.assertEqual(key, definition.key)
                self.assertEqual(definition.version, '1')
                self.assertTrue(definition.provenance)
                self.assertTrue(definition.evidence_requests)
                self.assertTrue(definition.investigation_checks)
                if key != FALLBACK:
                    self.assertTrue(definition.source_url.startswith('https://'))
                    self.assertIn('automation', definition.adaptation_note.lower())
        self.assertEqual(evidence_status(), 'unavailable')
        self.assertEqual(evidence_status(coverage_confirmed=False), 'unavailable')
        self.assertEqual(evidence_status(coverage_confirmed=True), 'not_observed')
        self.assertEqual(evidence_status(observed=True), 'observed')

    def test_authentication_fixture_group_and_selection_snapshot(self):
        ids = self.ingest('authentication')
        with app.app_context():
            group = group_context(self.db, ids[0])
        self.assertEqual(group['alert_ids'], ids[:2])
        execution, fake = self.retrieve_without_network(ids[0])
        row = self.db.execute('SELECT * FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution,)).fetchone()
        self.assertEqual(row['selected_playbook_key'], AUTH)
        self.assertEqual(row['group_occurrences'], 2)
        self.assertIn('authentication', row['selection_reason'].lower())
        self.assertIn('authentication_failed', json.loads(row['matched_triggers_json']))
        self.assertEqual(fake.search_documents.call_count, 1)
        html = self.client().get(f'/investigations/archive/{execution}').data.decode()
        self.assertIn('Authentication Investigation', html)
        self.assertIn('Why selected', html)
        self.assertIn('Brute Force Investigation - Generic', html)
        self.assertNotIn('authentication_review_v1', html)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0], 0)

    def test_file_and_process_fixture_selects_specialized_method_without_verdict(self):
        ids = self.ingest('file_process')
        execution, _ = self.retrieve_without_network(ids[0])
        row = self.db.execute('SELECT * FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution,)).fetchone()
        self.assertEqual(row['selected_playbook_key'], FILE_PROCESS)
        pivots = json.loads(row['pivots_json'])
        self.assertIn('C:\\Temp\\sample.bin', pivots['file_path'])
        self.assertIn('sysmon_eid11_detections', pivots['rule_groups'])
        self.assertIn('Sysmon Event 11', json.loads(row['matched_triggers_json']))
        html = self.client().get(f'/investigations/archive/{execution}').data.decode()
        self.assertIn('Suspicious File / Process Investigation', html)
        self.assertIn('It does not confirm malware', html)
        self.assertIn('MISP Malware triage playbooks', html)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_findings').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0], 0)

    def test_remote_fixture_two_agents_remain_separate_and_no_cross_host_claim(self):
        ids = self.ingest('remote_access')
        with app.app_context():
            first = group_context(self.db, ids[0])
            second = group_context(self.db, ids[1])
        self.assertEqual(first['alert_ids'], [ids[0]])
        self.assertEqual(second['alert_ids'], [ids[1]])
        execution, fake = self.retrieve_without_network(ids[0])
        row = self.db.execute('SELECT * FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution,)).fetchone()
        self.assertEqual(row['selected_playbook_key'], REMOTE_ACCESS)
        self.assertIn('MITRE T1021.001', json.loads(row['matched_triggers_json']))
        self.assertEqual(fake.search_documents.call_args.args[0]['query']['bool']['filter'][0],
                         {'term': {'agent.id': '001'}})
        self.assertEqual(evidence_status(coverage_confirmed=False), 'unavailable')
        self.assertEqual(row['cross_retrieval_status'], 'unavailable')
        self.assertIn('bounded cross-agent archive query',
                      self.client().get(f'/investigations/archive/{execution}').data.decode())

    def test_fallback_and_ambiguous_routing_do_not_use_description_keywords(self):
        ids = self.ingest('fallback')
        execution, _ = self.retrieve_without_network(ids[0])
        row = self.db.execute('SELECT * FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution,)).fetchone()
        self.assertEqual(row['selected_playbook_key'], FALLBACK)
        self.assertEqual(json.loads(row['matched_triggers_json']), [])
        self.assertIn('No dedicated playbook matched', row['selection_reason'])
        self.assertIn('Generic Evidence Review selected', row['selection_reason'])
        misleading = {'rule_description': 'SSH malware process brute force',
                      'mitre_ids': ['T1021.invalid']}
        self.assertEqual(select_playbook(misleading, {'rule_groups': ['system_error']}).playbook.key,
                         FALLBACK)
        mixed = select_playbook({'mitre_ids': ['T1021.001']},
                                {'rule_groups': ['authentication_success']})
        self.assertEqual(mixed.playbook.key, REMOTE_ACCESS)
        self.assertEqual(mixed, select_playbook({'mitre_ids': ['T1021.001']},
                                                {'rule_groups': ['authentication_success']}))

    def test_existing_phase_five_investigation_and_task_two_remain_compatible(self):
        auth_ids = self.ingest('authentication')
        auth_case = self.db.execute('SELECT incident_id FROM incident_alerts WHERE alert_id=?',
                                    (auth_ids[0],)).fetchone()[0]
        existing = run_investigation(auth_case)
        self.assertEqual(self.db.execute('SELECT playbook_key FROM investigations WHERE id=?',
                                         (existing,)).fetchone()[0], LEGACY_AUTH)
        file_ids = self.ingest('file_process')
        file_case = self.db.execute('SELECT incident_id FROM incident_alerts WHERE alert_id=?',
                                    (file_ids[0],)).fetchone()[0]
        prior = run_investigation(file_case)
        self.assertEqual(self.db.execute('SELECT playbook_key FROM investigations WHERE id=?',
                                         (prior,)).fetchone()[0], FILE_PROCESS)
        execution, _ = self.retrieve_without_network(file_ids[0])
        self.assertEqual(self.db.execute('SELECT playbook_key FROM investigations WHERE id=?',
                                         (execution,)).fetchone()[0],
                         'wazuh_archive_retrieval_v1')
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_migration_is_additive_and_idempotent(self):
        ids = self.ingest('fallback')
        before = self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        with self.db:
            migrate_archive_evidence(self.db)
            migrate_archive_evidence(self.db)
        names = {row[1] for row in self.db.execute('PRAGMA table_info(investigation_archive_runs)')}
        self.assertTrue({'selected_playbook_key', 'selection_reason',
                         'matched_triggers_json'} <= names)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], before)
        self.assertIsNotNone(self.db.execute('SELECT id FROM alerts WHERE id=?', (ids[0],)).fetchone())
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])


if __name__ == '__main__':
    unittest.main()
