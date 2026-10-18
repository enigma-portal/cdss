"""Phase 3 source provenance and supplementary isolation regression tests."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest

import app.database as database
from app.database.seed import seed_knowledge_base
from app.services.incident_processor import process_alert
from app.services.mitre_mapping import (
    attach_alert_context, get_alert_mitre_context, get_incident_mitre_context,
    record_alert_mappings, source_techniques,
)
from app.services.recommendation_engine import rebuild_recommendations


class MitreMappingTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.original = database.DATABASE
        database.DATABASE = Path(self.directory.name) / 'mapping.db'
        seed_knowledge_base()
        self.db = database.get_db_connection()

    def tearDown(self):
        self.db.close()
        database.DATABASE = self.original
        self.directory.cleanup()

    def event(self, identifier='a', ids=None, rule='test-rule'):
        event = {'id': identifier, 'timestamp': '2026-09-21T10:00:00Z',
                 'rule': {'id': rule, 'level': 8, 'groups': ['authentication_failed']}}
        if ids is not None:
            event['rule']['mitre'] = {'id': ids}
        return event

    def mapping(self, **changes):
        # Synthetic test-only approval. No production rule mapping is seeded.
        values = dict(wazuh_rule_id='test-rule', technique_id='T1110',
                      wazuh_reference='https://example.test/verified-test-rule',
                      mitre_reference='https://attack.mitre.org/techniques/T1110/',
                      rationale='Synthetic fixture only', enabled=1,
                      verification_status='verified', approval_status='approved',
                      verified_at='2026-09-21', approved_at='2026-09-21')
        values.update(changes)
        with self.db:
            self.db.execute('INSERT INTO supplementary_mitre_mappings (' +
                            ','.join(values) + ') VALUES (' + ','.join('?' for _ in values) + ')',
                            tuple(values.values()))

    def alert_id(self, identifier='a'):
        return self.db.execute('SELECT id FROM alerts WHERE wazuh_alert_id=?', (identifier,)).fetchone()[0]

    def test_source_order_duplicates_provenance_and_compatibility(self):
        result = process_alert(self.event(ids=['T1059.001','t1110','T1110','bad','T١١١٠']))
        context = get_alert_mitre_context(self.db, self.alert_id())
        self.assertEqual([r['technique_id'] for r in context['mappings']], ['T1059.001','T1110'])
        self.assertTrue(all(r['mapping_source'] == 'wazuh' for r in context['mappings']))
        self.assertTrue(all(r['source_reference'] == 'raw_alert:rule.mitre.id' for r in context['mappings']))
        self.assertEqual(self.db.execute('SELECT mitre_id FROM alerts').fetchone()[0], 'T1059.001')
        self.assertEqual(self.db.execute('SELECT technique_id FROM incidents').fetchone()[0], 'T1059.001')
        process_alert(self.event(ids=['T1110']))  # Immutable stored source wins.
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alert_mitre_techniques').fetchone()[0], 2)
        self.assertEqual(len(get_incident_mitre_context(self.db, result['incident_id'])['techniques']), 2)

    def test_not_mapped_keeps_wazuh_category(self):
        result = process_alert(self.event(ids=['invalid', 'T１２３４']))
        self.assertEqual(get_alert_mitre_context(self.db, self.alert_id())['status'], 'Not Mapped')
        self.assertEqual(get_incident_mitre_context(self.db, result['incident_id'])['status'], 'Not Mapped')
        self.assertEqual(self.db.execute('SELECT classification_source FROM incidents').fetchone()[0], 'WAZUH_GROUP')

    def test_unknown_syntax_valid_id_is_retained_without_invented_tactic_or_weight(self):
        process_alert(self.event(ids=['T9999']))
        row = self.db.execute("SELECT * FROM mitre_techniques WHERE technique_id='T9999'").fetchone()
        self.assertEqual(row['catalogue_source'], 'placeholder')
        self.assertIsNone(row['tactic'])
        self.assertIsNone(self.db.execute("SELECT * FROM knowledge_base WHERE technique_id='T9999'").fetchone())
        self.assertEqual(self.db.execute('SELECT risk_basis FROM incidents').fetchone()[0], 'WAZUH_ONLY')

    def test_approved_supplementary_context_does_not_change_legacy_score_or_rebuild(self):
        before = process_alert(self.event('baseline'))
        baseline_guidance = [tuple(r) for r in self.db.execute(
            'SELECT action_text,rationale FROM incident_recommendations WHERE incident_id=? ORDER BY priority',
            (before['incident_id'],))]
        # Restore empty ingestion state so frequency is identical in both runs.
        with self.db:
            self.db.execute('DELETE FROM incidents')
            self.db.execute('DELETE FROM alerts')
        self.mapping()
        after = process_alert(self.event())
        self.assertEqual(before['risk_score'], after['risk_score'])
        row = self.db.execute('SELECT technique_id,risk_basis,classification_source FROM incidents').fetchone()
        self.assertEqual(tuple(row), (None, 'WAZUH_ONLY', 'WAZUH_GROUP'))
        self.assertIsNone(self.db.execute('SELECT mitre_id FROM alerts').fetchone()[0])
        context = get_incident_mitre_context(self.db, after['incident_id'])
        self.assertEqual(context['techniques'][0]['sources'][0]['mapping_source'], 'supplementary')
        with self.db:
            rebuild_recommendations(self.db)
        self.assertEqual(baseline_guidance, [tuple(r) for r in self.db.execute(
            'SELECT action_text,rationale FROM incident_recommendations ORDER BY priority')])
        database.initialize_database()
        self.assertEqual(self.db.execute('SELECT risk_basis FROM incidents').fetchone()[0], 'WAZUH_ONLY')

    def test_valid_wazuh_mapping_has_precedence(self):
        self.mapping()
        process_alert(self.event(ids=['T1059']))
        mappings = get_alert_mitre_context(self.db, self.alert_id())['mappings']
        self.assertEqual([(r['technique_id'],r['mapping_source']) for r in mappings], [('T1059','wazuh')])

    def test_unapproved_unverified_disabled_or_invalid_reference_is_ignored(self):
        for changes in ({'enabled':0}, {'verification_status':'unverified'},
                        {'approval_status':'pending'}, {'verified_at':'invalid'},
                        {'mitre_reference':'https://example.test/T1110'},
                        {'mitre_reference':'https://attack.mitre.org/techniques/T1059/'}):
            with self.subTest(changes=changes):
                with self.db:
                    self.db.execute('DELETE FROM supplementary_mitre_mappings')
                self.mapping(**changes)
                result = process_alert(self.event(str(changes)))
                self.assertEqual(get_incident_mitre_context(self.db, result['incident_id'])['status'], 'Not Mapped')

    def test_no_keyword_group_or_near_rule_inference(self):
        self.mapping()
        process_alert(self.event(rule='test-rule-other'))
        self.assertEqual(get_alert_mitre_context(self.db,self.alert_id())['status'], 'Not Mapped')

    def test_aggregation_retains_all_contributing_alerts(self):
        first = process_alert(self.event('first', ['T1110']))
        process_alert(self.event('second', ['T1110','T1059']))
        with self.db:
            attach_alert_context(self.db, first['incident_id'], self.alert_id('second'))
            attach_alert_context(self.db, first['incident_id'], self.alert_id('second'))
        context = get_incident_mitre_context(self.db, first['incident_id'])
        self.assertEqual([t['technique_id'] for t in context['techniques']], ['T1110','T1059'])
        self.assertEqual(len(context['techniques'][0]['sources']), 2)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_migration_backfills_source_only_and_is_idempotent(self):
        process_alert(self.event(ids=['T1110','T1059']))
        process_alert(self.event('unmapped'))
        snapshot = [tuple(r) for r in self.db.execute('SELECT * FROM risk_scores ORDER BY id')]
        with self.db:
            self.db.execute('DELETE FROM alert_mitre_techniques')
        self.mapping()
        database.initialize_database()
        database.initialize_database()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alert_mitre_techniques').fetchone()[0], 2)
        self.assertEqual(get_alert_mitre_context(self.db,self.alert_id('unmapped'))['status'], 'Not Mapped')
        self.assertEqual(snapshot, [tuple(r) for r in self.db.execute('SELECT * FROM risk_scores ORDER BY id')])
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_raw_source_precedence_and_normalized_fallback(self):
        self.assertEqual(source_techniques(json.dumps(self.event()), '["T1110"]')[0], ())
        self.assertEqual(source_techniques('legacy unavailable', '["T1110"]')[0], ('T1110',))

    def test_database_rejects_duplicate_or_dangling_provenance(self):
        process_alert(self.event(ids=['T1110']))
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute("INSERT INTO alert_mitre_techniques(alert_id,technique_id,mapping_source,ordinal,source_reference) VALUES(?, 'T1110','wazuh',0,'duplicate')", (self.alert_id(),))
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute("INSERT INTO incident_mitre_sources(incident_id,technique_id,source_alert_id,mapping_source) VALUES(999,'T1110',999,'wazuh')")
