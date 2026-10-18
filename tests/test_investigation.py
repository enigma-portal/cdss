"""Phase 5 observations, execution history, UI safety and legacy isolation."""
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from run import app
import app.database as database
from app.database.seed import seed_knowledge_base
from app.database.phase5 import migrate_investigations
from app.services.incident_processor import process_alert
from app.services.investigation import run_investigation, investigation_history, AUTH, FALLBACK


class InvestigationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original = database.DATABASE
        database.DATABASE = Path(self.temp.name) / 'investigation.db'
        seed_knowledge_base()
        self.db = database.get_db_connection()
        with self.db:
            self.db.execute('''INSERT INTO assets(asset_name,asset_type,asset_role,os_family,os_name,
                wazuh_agent_id,criticality,is_protected)
                VALUES('lab','Server','Other','Other','Other','001','critical',1)''')

    def tearDown(self):
        self.db.close()
        database.DATABASE = self.original
        self.temp.cleanup()

    def add(self, name, minute=0, groups=None, user='alice', source='192.0.2.1',
            agent='001', mitre=None, firedtimes=1):
        event = {'id': name, 'timestamp': f'2026-09-26T12:{minute:02d}:00Z',
            'agent': {'id': agent}, 'rule': {'id': name, 'level': 8,
            'description': 'Source description ' + name,
            'groups': groups if groups is not None else ['authentication_failed'], 'firedtimes': firedtimes},
            'data': {'srcuser': user, 'srcip': source}}
        if mitre:
            event['rule']['mitre'] = {'id': mitre}
        result = process_alert(event)
        aid = self.db.execute('SELECT id FROM alerts WHERE wazuh_alert_id=?', (name,)).fetchone()[0]
        return result['incident_id'], aid

    def run_checks(self, incident):
        execution = run_investigation(incident)
        rows = self.db.execute('SELECT * FROM investigation_findings WHERE investigation_id=?', (execution,))
        result = {r['finding_key']: {**dict(r), 'value': json.loads(r['finding_value'])} for r in rows}
        return execution, result

    def test_historical_windows_logon_fields_reach_findings_without_db_backfill(self):
        event = {'id':'windows-nested-account', 'timestamp':'2026-09-26T12:00:00Z',
                 'agent':{'id':'001'},
                 'rule':{'id':'60122','level':5,'description':'Logon failure',
                         'groups':['windows_security','authentication_failed']},
                 'data':{'win':{'system':{'eventID':'4625'},
                                'eventdata':{'targetUserName':'LAB\\alice',
                                             'ipAddress':'192.0.2.77'}}}}
        incident = process_alert(event)['incident_id']
        alert = self.db.execute("SELECT id,username,source_ip FROM alerts WHERE wazuh_alert_id='windows-nested-account'").fetchone()
        self.assertEqual((alert['username'],alert['source_ip']),('LAB\\alice','192.0.2.77'))
        # Simulate an alert saved before these explicit Wazuh fields were normalized.
        with self.db:
            self.db.execute('UPDATE alerts SET username=NULL,source_ip=NULL WHERE id=?',(alert['id'],))
        execution, findings = self.run_checks(incident)
        self.assertEqual(findings['authentication_accounts']['finding_status'],'observed')
        self.assertEqual(findings['authentication_accounts']['value']['accounts'],['LAB\\alice'])
        self.assertEqual(findings['shared_failure_source']['value']['sources'],{'192.0.2.77':[alert['id']]})
        self.assertIsNone(self.db.execute('SELECT username FROM alerts WHERE id=?',(alert['id'],)).fetchone()[0])
        from app.services.contextual_risk import assess_investigation
        assessment_id = assess_investigation(incident,execution)
        self.assertEqual(self.db.execute('SELECT evidence_state FROM risk_assessments WHERE id=?',
                                         (assessment_id,)).fetchone()[0],'T1')

    def refs(self, finding):
        return {r[0] for r in self.db.execute(
            'SELECT alert_id FROM investigation_finding_alerts WHERE finding_id=?', (finding['id'],))}

    def snapshot(self):
        return {t: [tuple(r) for r in self.db.execute('SELECT * FROM '+t+' ORDER BY rowid')]
            for t in ('alerts', 'incidents', 'risk_scores', 'incident_recommendations', 'knowledge_base',
                      'incident_alerts', 'incident_mitre_techniques')}

    def test_migration_preserves_records_and_is_idempotent(self):
        incident, _ = self.add('legacy')
        before = self.snapshot()
        with self.db:
            # Only this isolated temporary fixture: simulate a pre-Phase-5 DB.
            self.db.execute('DROP TABLE investigation_finding_alerts')
            self.db.execute('DROP TABLE investigation_findings')
            self.db.execute('DROP TABLE investigations')
            migrate_investigations(self.db)
            migrate_investigations(self.db)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0], 0)
        execution, findings = self.run_checks(incident)
        self.assertGreater(len(findings), 3)
        self.assertEqual(self.db.execute('SELECT incident_id,status FROM investigations WHERE id=?',
                                        (execution,)).fetchone()[:], (incident, 'completed'))

    def test_constraints_foreign_keys_and_json(self):
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute("INSERT INTO investigations(incident_id,playbook_key,status) VALUES(999,'x','completed')")
        incident, _ = self.add('a')
        execution, findings = self.run_checks(incident)
        for status in ('benign', 'T1', 'unknown'):
            with self.assertRaises(sqlite3.IntegrityError), self.db:
                self.db.execute('UPDATE investigation_findings SET finding_status=?', (status,))
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute("UPDATE investigation_findings SET finding_value='not json'")
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute("UPDATE investigations SET status='malicious'")
        with self.assertRaises(sqlite3.IntegrityError), self.db:
            self.db.execute('INSERT INTO investigation_finding_alerts VALUES(?,999999)',
                            (findings['authentication_failures']['id'],))

    def test_real_alert_counts_not_firedtimes_and_traceability(self):
        incident, a = self.add('a', firedtimes=999999)
        _, b = self.add('b', minute=1, firedtimes=88888)
        _, findings = self.run_checks(incident)
        failure = findings['authentication_failures']
        self.assertEqual(failure['value']['observed_alert_count'], 2)
        self.assertEqual(self.refs(failure), {a,b})
        self.assertEqual(findings['shared_failure_source']['finding_status'], 'observed')
        self.assertEqual(findings['authentication_accounts']['value']['accounts'], ['alice'])
        self.assertEqual(findings['successful_authentication']['finding_status'], 'not_observed')
        self.assertEqual(findings['post_authentication_related_detections']['finding_status'], 'not_observed')

    def test_all_members_temporal_sequence_not_insertion_order(self):
        incident, success = self.add('success', minute=5, groups=['authentication_success'])
        _, later = self.add('file-change', minute=6, groups=['syscheck'])
        _, failure = self.add('failure', minute=1)
        _, findings = self.run_checks(incident)
        self.assertEqual([a['id'] for a in findings['linked_alert_evidence']['value']], [failure,success,later])
        sequence = findings['successful_authentication_after_failures']
        self.assertEqual(sequence['value'], [{'before_alert_id':failure,'after_alert_id':success}])
        self.assertEqual(self.refs(sequence), {failure,success})
        post = findings['post_authentication_related_detections']
        self.assertEqual(post['finding_status'], 'observed')
        self.assertEqual(post['value']['detections'][0]['rule_id'], 'file-change')
        self.assertEqual(self.refs(post), {success,later})

    def test_success_before_or_equal_failures_not_after(self):
        incident, _ = self.add('success', minute=1, groups=['authentication_success'])
        self.add('failure', minute=2)
        self.add('equal-success', minute=2, groups=['authentication_success'])
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['successful_authentication']['finding_status'], 'observed')
        self.assertEqual(findings['successful_authentication_after_failures']['finding_status'], 'not_observed')

    def test_timezone_equivalence_and_missing_timestamp(self):
        incident, _ = self.add('failure')
        _, success = self.add('success', minute=1, groups=['authentication_success'])
        with self.db:
            self.db.execute("UPDATE alerts SET event_timestamp='2026-09-26T17:00:00+05:00' WHERE id=?", (success,))
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['successful_authentication_after_failures']['finding_status'], 'not_observed')
        with self.db:
            self.db.execute("UPDATE alerts SET event_timestamp='unavailable' WHERE id=?", (success,))
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['successful_authentication_after_failures']['finding_status'], 'unavailable')

    def test_conflicting_accounts_do_not_claim_related_success(self):
        incident, _ = self.add('failure', user='alice')
        self.add('success', minute=1, user='bob', groups=['authentication_success'])
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['successful_authentication_after_failures']['finding_status'], 'not_observed')

    def test_missing_source_and_account_not_inferred(self):
        incident, _ = self.add('failure', source=None, user=None)
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['shared_failure_source']['finding_status'], 'unavailable')
        self.assertEqual(findings['authentication_accounts']['finding_status'], 'unavailable')

    def test_missing_entity_prevents_sequence_claim(self):
        incident, _ = self.add('failure')
        self.add('success', minute=1, groups=['authentication_success'])
        with self.db:
            self.db.execute("UPDATE alerts SET source_ip=NULL,username=NULL,raw_alert=json_remove(raw_alert,'$.data.srcip','$.data.srcuser')")
        _, findings = self.run_checks(incident)
        sequence = findings['successful_authentication_after_failures']
        self.assertEqual(sequence['finding_status'], 'unavailable')
        self.assertEqual(sequence['value'], [])

    def test_success_sequence_never_creates_verdict_or_risk(self):
        incident, _ = self.add('failure')
        self.add('success', minute=1, groups=['authentication_success'])
        before = self.snapshot()
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['successful_authentication_after_failures']['finding_status'], 'observed')
        values = json.dumps([f['value'] for f in findings.values()]).lower()
        for forbidden in ('compromised', 'attack succeeded', 'confirmed malicious', 'confidence', 'risk_level'):
            self.assertNotIn(forbidden, values)
        self.assertEqual(before, self.snapshot())

    def test_pre_auth_activity_and_unrelated_identity_not_reported_after(self):
        incident, _ = self.add('file-before', groups=['syscheck'])
        self.add('success', minute=1, groups=['authentication_success'])
        self.add('other-account', minute=2, user='bob', groups=['syscheck'])
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['post_authentication_related_detections']['finding_status'], 'not_observed')

    def test_fallback_not_keyword_or_mitre_selected(self):
        incident, _ = self.add('brute-force-password-login', groups=['syscheck'], mitre=['T1110'])
        execution, findings = self.run_checks(incident)
        self.assertEqual(self.db.execute('SELECT playbook_key FROM investigations WHERE id=?', (execution,)).fetchone()[0], FALLBACK)
        self.assertIn('no_specific_playbook', findings)
        self.assertNotIn('authentication_failures', findings)

    def test_asset_snapshot_and_mitre_provenance(self):
        incident, _ = self.add('a', mitre=['T1110','T1059.001'])
        execution, findings = self.run_checks(incident)
        self.assertEqual(self.db.execute('SELECT playbook_key FROM investigations WHERE id=?', (execution,)).fetchone()[0], AUTH)
        self.assertEqual(findings['asset_context']['value']['criticality'], 'critical')
        self.assertEqual(findings['asset_context']['value']['is_protected'], 1)
        mappings = findings['mitre_context']['value']['alerts'][0]['mappings']
        self.assertEqual([m['technique_id'] for m in mappings], ['T1110','T1059.001'])
        self.assertTrue(all(m['mapping_source'] == 'wazuh' for m in mappings))
        with self.db:
            self.db.execute("UPDATE assets SET criticality='low',is_protected=0")
        _, newer = self.run_checks(incident)
        self.assertEqual(newer['asset_context']['value']['is_protected'], 0)
        old = self.db.execute('SELECT finding_value FROM investigation_findings WHERE id=?', (findings['asset_context']['id'],)).fetchone()[0]
        self.assertEqual(json.loads(old)['criticality'], 'critical')

    def test_unmapped_asset_and_mitre_still_investigable(self):
        incident, _ = self.add('a', agent='unknown')
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['asset_context']['finding_status'], 'unavailable')
        self.assertIsNone(findings['asset_context']['value'])
        self.assertEqual(findings['mitre_context']['value']['status'], 'Not Mapped')

    def test_partial_and_conflicting_groups_safe(self):
        incident, _ = self.add('failure')
        self.add('partial', groups=[])
        self.add('conflicting', groups=['authentication_failed','authentication_success'])
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['authentication_failures']['value']['observed_alert_count'], 1)
        self.assertEqual(findings['successful_authentication']['finding_status'], 'unavailable')
        with self.db:
            self.db.execute("UPDATE alerts SET rule_groups='invalid json'")
        execution, findings = self.run_checks(incident)
        self.assertIn('no_specific_playbook', findings)

    def test_no_cross_incident_evidence(self):
        first, a = self.add('a', user='alice', source='192.0.2.1')
        second, b = self.add('b', user='bob', source='192.0.2.2', groups=['authentication_success'])
        self.assertNotEqual(first, second)
        _, findings = self.run_checks(first)
        self.assertEqual(self.refs(findings['linked_alert_evidence']), {a})
        self.assertEqual(findings['successful_authentication']['finding_status'], 'not_observed')

    def test_rerun_history_and_legacy_isolation_no_risk_states(self):
        incident, _ = self.add('a')
        before = self.snapshot()
        first, old = self.run_checks(incident)
        second, newer = self.run_checks(incident)
        self.assertNotEqual(first, second)
        self.assertEqual(before, self.snapshot())
        history = investigation_history(self.db, incident)
        self.assertEqual([h['id'] for h in history], [second,first])
        self.assertEqual(len(old), len(newer))
        self.assertFalse(any(k in old for k in ('risk','confidence','T1','T2','T3','T4')))
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_failed_execution_atomic_and_retry_safe(self):
        incident, _ = self.add('a')
        before = self.snapshot()
        with patch('app.services.investigation._build_findings', side_effect=ValueError('secret test value')):
            with self.assertRaises(ValueError):
                run_investigation(incident)
        self.assertEqual(self.db.execute('SELECT status FROM investigations').fetchone()[0], 'failed')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_findings').fetchone()[0], 0)
        self.run_checks(incident)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0], 2)

    def test_mid_write_failure_rolls_back_all_findings(self):
        incident, _ = self.add('a')
        with self.db:
            self.db.execute('''CREATE TRIGGER test_finding_failure BEFORE INSERT ON investigation_findings
                WHEN NEW.finding_key='asset_context' BEGIN SELECT RAISE(ABORT,'test failure'); END''')
        with self.assertRaises(sqlite3.IntegrityError):
            run_investigation(incident)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_findings').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_finding_alerts').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT status FROM investigations').fetchone()[0], 'failed')

    def test_empty_membership_does_not_use_legacy_seed(self):
        incident, _ = self.add('a')
        with self.db:
            self.db.execute('DELETE FROM incident_alerts')
        _, findings = self.run_checks(incident)
        self.assertEqual(findings['linked_alert_evidence']['finding_status'], 'unavailable')
        self.assertIn('no_specific_playbook', findings)

    def client(self):
        with self.db:
            uid = self.db.execute("INSERT INTO users(username,password_hash,role) VALUES('analyst-test','unused','analyst')").lastrowid
        client = app.test_client()
        with client.session_transaction() as session:
            session['user_id'] = uid
            session['csrf_token'] = 'test-token'
        return client

    def test_ui_execution_history_refresh_auth_csrf_and_escaping(self):
        incident, _ = self.add('a', user='<script>alert(1)</script>')
        path = f'/incidents/{incident}/investigations'
        self.assertEqual(app.test_client().post(path).status_code, 302)
        client = self.client()
        self.assertEqual(client.post(path).status_code, 400)
        self.assertEqual(client.get(path).status_code, 405)
        response = client.post(path, data={'csrf_token':'test-token'}, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Investigation Approach', response.data)
        self.assertNotIn(AUTH.encode(), response.data)
        self.assertIn(b'&lt;script&gt;', response.data)
        self.assertNotIn(b'<script>alert(1)</script>', response.data)
        for _ in range(2):
            self.assertEqual(client.get(f'/incidents/{incident}').status_code, 200)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0], 1)
        client.post(path, data={'csrf_token':'test-token'})
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigations').fetchone()[0], 2)

    def test_ui_failure_sanitized_and_missing_incident(self):
        incident, _ = self.add('a')
        client = self.client()
        with patch('app.routes.dashboard.run_investigation', side_effect=RuntimeError('password=secret-value')):
            response = client.post(f'/incidents/{incident}/investigations', data={'csrf_token':'test-token'}, follow_redirects=True)
        self.assertNotIn(b'secret-value', response.data)
        self.assertIn(b'Investigation failed', response.data)
        self.assertEqual(client.post('/incidents/99999/investigations', data={'csrf_token':'test-token'}).status_code, 404)


if __name__ == '__main__':
    unittest.main()
