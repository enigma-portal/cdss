"""Approved Phase 6 matrix, evidence boundaries, confidence, history and isolation."""
import json
import sqlite3
import unittest
from unittest.mock import patch

import test_investigation as fixtures
from run import app
from app.database.phase6 import migrate_risk_assessments
from app.services.investigation import run_investigation
from app.services.contextual_risk import (
    assess_investigation, create_initial_assessment, current_assessment,
    assessment_history, matrix_risk, VERSION, _file_state,
)
from app.services.investigation import _file_events


class ContextualRiskTests(unittest.TestCase):
    setUp = fixtures.InvestigationTests.setUp
    tearDown = fixtures.InvestigationTests.tearDown
    add = fixtures.InvestigationTests.add
    client = fixtures.InvestigationTests.client
    snapshot = fixtures.InvestigationTests.snapshot

    def assess(self, incident):
        investigation = run_investigation(incident)
        aid = assess_investigation(incident, investigation)
        return dict(self.db.execute('SELECT * FROM risk_assessments WHERE id=?', (aid,)).fetchone())

    def sequence(self, stage=3, user='alice', source='192.0.2.1'):
        incident, _ = self.add('failure-one', user=user, source=source)
        if stage >= 2:
            self.add('failure-two', minute=1, user=user, source=source)
        if stage >= 3:
            self.add('success', minute=2, groups=['authentication_success'], user=user, source=source)
        if stage >= 4:
            self.add('integrity-change', minute=3, groups=['syscheck'], user=user, source=source)
        return incident

    def test_schema_additive_migration_and_version(self):
        incident = self.sequence(1)
        before = self.snapshot()
        with self.db:
            migrate_risk_assessments(self.db)
            migrate_risk_assessments(self.db)
        self.assertEqual(before, self.snapshot())
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0], 0)
        result = self.assess(incident)
        self.assertEqual(result['methodology_version'], VERSION)
        self.assertEqual(result['assessment_stage'], 'contextual')
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])
        for column, value in [('evidence_state','T5'),('confidence','100'),('risk_level','severe')]:
            with self.assertRaises(sqlite3.IntegrityError), self.db:
                self.db.execute('UPDATE risk_assessments SET '+column+'=? WHERE id=?', (value,result['id']))

    def test_all_sixteen_matrix_cells(self):
        expected = {'T1':['low','low','medium','medium'], 'T2':['low','medium','high','high'],
                    'T3':['medium','high','high','critical'], 'T4':['medium','high','critical','critical']}
        for state, risks in expected.items():
            for criticality,risk in zip(['low','medium','high','critical'],risks):
                with self.subTest(state=state, criticality=criticality):
                    self.assertEqual(matrix_risk(state,criticality,True),risk)
                    self.assertIsNone(matrix_risk(state,criticality,False))
        self.assertIsNone(matrix_risk('Inconclusive','critical',True))
        self.assertIsNone(matrix_risk('T4',None,True))

    def test_multiple_file_alerts_do_not_claim_only_one_observation(self):
        evidence = {identifier: {'id': identifier, 'event_timestamp': f'2026-10-09T07:0{identifier}:00Z',
            'agent_id': '001', 'asset_id': 1, 'source_ip': None, 'username': None,
            'rule_groups': ['sysmon_eid11_detections'],
            'source_fields': {'file_path': f'C:/Temp/item-{identifier}.zip'}}
            for identifier in (1, 2)}
        observations = _file_events(evidence.values())
        state, decisive, rationale = _file_state({'file_process_events': {
            'value': observations, 'status': 'observed', 'refs': {1, 2}}}, evidence)
        self.assertEqual(state, 'T1')
        self.assertEqual(decisive, [1])
        self.assertIn('2 structured file/process observations', rationale)

    def test_initial_record_severity_context_only(self):
        incident = self.sequence(2)
        with self.db:
            self.db.execute("UPDATE alerts SET rule_level=14 WHERE wazuh_alert_id='failure-two'")
        aid = create_initial_assessment(incident)
        row = self.db.execute('SELECT * FROM risk_assessments WHERE id=?',(aid,)).fetchone()
        self.assertEqual(row['assessment_stage'],'initial')
        self.assertEqual(json.loads(row['inputs_snapshot'])['highest_wazuh_rule_level'],14)
        self.assertEqual(row['asset_criticality_snapshot'],'critical')
        self.assertIsNone(row['risk_level'])
        self.assertIsNone(row['evidence_state'])
        self.assertIsNone(current_assessment(self.db,incident))
        self.assertIn('Preliminary', row['rationale'])

    def test_t1_isolated_failure(self):
        result = self.assess(self.sequence(1))
        self.assertEqual((result['evidence_state'],result['risk_level']),('T1','medium'))

    def test_t2_repeated_failures_never_t3(self):
        result = self.assess(self.sequence(2))
        self.assertEqual((result['evidence_state'],result['risk_level']),('T2','high'))

    def test_t3_related_success_no_compromise_verdict(self):
        result = self.assess(self.sequence(3))
        self.assertEqual((result['evidence_state'],result['risk_level']),('T3','critical'))
        self.assertIn('not a confirmed compromise verdict', result['rationale'])

    def test_t4_requires_actual_linked_post_outcome_security_activity(self):
        result = self.assess(self.sequence(4))
        self.assertEqual(result['evidence_state'],'T4')
        self.assertEqual(len(json.loads(result['inputs_snapshot'])['decisive_alert_ids']),4)

    def test_unrelated_success_never_t3(self):
        incident = self.sequence(2)
        self.add('other-user-success',minute=2,user='bob',groups=['authentication_success'])
        self.assertEqual(self.assess(incident)['evidence_state'],'T2')

    def test_success_before_second_failure_does_not_establish_t3(self):
        incident = self.sequence(2)
        self.add('early-success',minute=0,groups=['authentication_success'])
        self.assertEqual(self.assess(incident)['evidence_state'],'T2')

    def test_generic_later_alert_not_automatically_t4(self):
        incident = self.sequence(3)
        self.add('generic-later',minute=3,groups=['windows'])
        result = self.assess(incident)
        self.assertEqual(result['evidence_state'],'T3')
        self.assertEqual(result['confidence'],'low')

    def test_security_activity_before_outcome_not_t4(self):
        incident = self.sequence(3)
        self.add('earlier-file-change',minute=0,groups=['syscheck'])
        self.assertEqual(self.assess(incident)['evidence_state'],'T3')

    def test_post_activity_must_follow_the_t3_success_not_an_unrelated_success(self):
        incident = self.sequence(3)
        self.add('bob-success',minute=3,user='bob',groups=['authentication_success'])
        self.add('bob-change',minute=4,user='bob',groups=['syscheck'])
        self.assertEqual(self.assess(incident)['evidence_state'],'T3')

    def test_success_only_inconclusive(self):
        incident,_ = self.add('normal-success',groups=['authentication_success'])
        result = self.assess(incident)
        self.assertEqual(result['evidence_state'],'Inconclusive')
        self.assertEqual(result['confidence'],'low')
        self.assertIsNone(result['risk_level'])

    def test_contradictory_and_empty_evidence_inconclusive(self):
        incident,_ = self.add('contradiction',groups=['authentication_failed','authentication_success'])
        self.add('normal-failure',minute=1)
        self.assertEqual(self.assess(incident)['evidence_state'],'Inconclusive')
        with self.db:
            self.db.execute('DELETE FROM incident_alerts')
        self.assertEqual(self.assess(incident)['evidence_state'],'Inconclusive')

    def test_generic_fallback_remains_inconclusive_without_dedicated_interpretation(self):
        incident,_ = self.add('file1',groups=['syscheck'])
        self.assertEqual(self.assess(incident)['evidence_state'],'Inconclusive')
        for minute in range(1,5):
            self.add('file'+str(minute+1),minute=minute,groups=['syscheck'])
        self.assertEqual(self.assess(incident)['evidence_state'],'Inconclusive')

    def test_fallback_unknown_groups_inconclusive_despite_severity(self):
        incident,_ = self.add('suspicious-malware-description',groups=['windows'],mitre=['T1110'])
        with self.db:
            self.db.execute('UPDATE alerts SET rule_level=15')
        result = self.assess(incident)
        self.assertEqual(result['evidence_state'],'Inconclusive')
        self.assertIsNone(result['risk_level'])

    def test_protected_asset_snapshot_and_history_after_edit(self):
        incident = self.sequence(3)
        investigation = run_investigation(incident)
        with self.db:
            self.db.execute("UPDATE assets SET criticality='low'")
        old = assess_investigation(incident,investigation)
        old_row = self.db.execute('SELECT * FROM risk_assessments WHERE id=?',(old,)).fetchone()
        self.assertEqual(old_row['asset_criticality_snapshot'],'critical')
        self.assertEqual(old_row['risk_level'],'critical')
        newer = self.assess(incident)
        self.assertEqual(newer['asset_criticality_snapshot'],'low')
        self.assertEqual(newer['risk_level'],'medium')
        self.assertEqual(current_assessment(self.db,incident)['id'],newer['id'])
        self.assertEqual(self.db.execute('SELECT risk_level FROM risk_assessments WHERE id=?',(old,)).fetchone()[0],'critical')

    def test_missing_asset_no_default_risk(self):
        incident,_ = self.add('unmapped',agent='unknown')
        result = self.assess(incident)
        self.assertIsNone(result['asset_criticality_snapshot'])
        self.assertIsNone(result['risk_level'])
        self.assertIn('mapped asset with valid administrator criticality is unavailable',result['rationale'])

    def test_unprotected_asset_no_contextual_risk(self):
        incident = self.sequence(3)
        with self.db:
            self.db.execute('UPDATE assets SET is_protected=0')
        result = self.assess(incident)
        self.assertEqual(result['evidence_state'],'T3')
        self.assertIsNone(result['risk_level'])

    def test_high_confidence_complete_direct_evidence(self):
        self.assertEqual(self.assess(self.sequence(3))['confidence'],'high')

    def test_medium_confidence_missing_nondecisive_username(self):
        result = self.assess(self.sequence(3,user=None))
        self.assertEqual((result['evidence_state'],result['risk_level'],result['confidence']),('T3','critical','medium'))

    def test_low_confidence_adjacent_outcome_unknown_does_not_reduce_risk(self):
        incident = self.sequence(2)
        self.add('unknown-event',minute=2,groups=[])
        result = self.assess(incident)
        self.assertEqual((result['evidence_state'],result['risk_level'],result['confidence']),('T2','high','low'))

    def test_severity_firedtimes_mitre_and_optional_ti_do_not_change_final_risk(self):
        incident = self.sequence(3)
        before = self.assess(incident)
        with self.db:
            self.db.execute('UPDATE alerts SET rule_level=15')
            for row in self.db.execute('SELECT id,raw_alert FROM alerts').fetchall():
                raw=json.loads(row['raw_alert']); raw['rule']['firedtimes']=999999
                self.db.execute('UPDATE alerts SET raw_alert=?,wazuh_mitre_ids=? WHERE id=?',
                                (json.dumps(raw),'["T1110","T1059.001"]',row['id']))
        investigation=run_investigation(incident)
        with self.db:
            self.db.execute('''INSERT INTO investigation_findings(investigation_id,finding_key,finding_type,
                finding_value,finding_status,rationale) VALUES(?,'optional_ti','context','null','unavailable','Optional')''',(investigation,))
        aid=assess_investigation(incident,investigation)
        after=dict(self.db.execute('SELECT * FROM risk_assessments WHERE id=?',(aid,)).fetchone())
        for key in ('evidence_state','risk_level','confidence'):
            self.assertEqual(before[key],after[key])

    def test_duplicate_event_representations_do_not_escalate(self):
        incident = self.sequence(1)
        self.add('duplicate-representation',minute=0)
        self.assertEqual(self.assess(incident)['evidence_state'],'T1')

    def test_legacy_data_preserved_and_execution_assessment_idempotent(self):
        incident = self.sequence(4)
        before=self.snapshot()
        result=self.assess(incident)
        again=assess_investigation(incident,result['investigation_id'])
        self.assertEqual(result['id'],again)
        self.assertEqual(before,self.snapshot())
        self.assertEqual(len(assessment_history(self.db,incident)),2)

    def test_missing_traceability_and_forged_count_inconclusive(self):
        incident=self.sequence(2)
        investigation=run_investigation(incident)
        with self.db:
            self.db.execute("UPDATE investigation_findings SET finding_value='{\"observed_alert_count\":900}' WHERE investigation_id=? AND finding_key='authentication_failures'",(investigation,))
        aid=assess_investigation(incident,investigation)
        self.assertEqual(self.db.execute('SELECT evidence_state FROM risk_assessments WHERE id=?',(aid,)).fetchone()[0],'Inconclusive')
        investigation=run_investigation(incident)
        with self.db:
            self.db.execute('DELETE FROM investigation_finding_alerts WHERE finding_id IN (SELECT id FROM investigation_findings WHERE investigation_id=?)',(investigation,))
        aid=assess_investigation(incident,investigation)
        self.assertIsNone(self.db.execute('SELECT risk_level FROM risk_assessments WHERE id=?',(aid,)).fetchone()[0])

    def test_failed_execution_rejected_and_cross_incident_fk_enforced(self):
        incident=self.sequence(1)
        investigation=run_investigation(incident)
        with self.db:
            self.db.execute("UPDATE investigations SET status='failed' WHERE id=?",(investigation,))
        with self.assertRaises(ValueError):
            assess_investigation(incident,investigation)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0],0)
        with self.db:
            self.db.execute("UPDATE investigations SET status='completed' WHERE id=?",(investigation,))
        aid=assess_investigation(incident,investigation)
        other,_=self.add('other',user='bob',source='192.0.2.2')
        with self.assertRaises(sqlite3.IntegrityError),self.db:
            self.db.execute('UPDATE risk_assessments SET incident_id=? WHERE id=?',(other,aid))

    def test_missing_adjacent_checks_low_confidence_not_high(self):
        incident=self.sequence(1)
        investigation=run_investigation(incident)
        with self.db:
            self.db.execute("DELETE FROM investigation_findings WHERE investigation_id=? AND finding_key='successful_authentication_after_failures'",(investigation,))
        aid=assess_investigation(incident,investigation)
        row=self.db.execute('SELECT * FROM risk_assessments WHERE id=?',(aid,)).fetchone()
        self.assertEqual(row['evidence_state'],'T1')
        self.assertEqual(row['confidence'],'low')

    def test_missing_criticality_in_snapshot_unassessed(self):
        incident=self.sequence(2)
        investigation=run_investigation(incident)
        with self.db:
            row=self.db.execute("SELECT id,finding_value FROM investigation_findings WHERE investigation_id=? AND finding_key='asset_context'",(investigation,)).fetchone()
            value=json.loads(row['finding_value']); value['criticality']=None
            self.db.execute('UPDATE investigation_findings SET finding_value=? WHERE id=?',(json.dumps(value),row['id']))
        aid=assess_investigation(incident,investigation)
        self.assertIsNone(self.db.execute('SELECT risk_level FROM risk_assessments WHERE id=?',(aid,)).fetchone()[0])

    def test_assessment_write_failure_atomic(self):
        incident=self.sequence(2)
        investigation=run_investigation(incident)
        with self.db:
            self.db.execute('''CREATE TRIGGER test_contextual_failure BEFORE INSERT ON risk_assessments
                WHEN NEW.assessment_stage='contextual' BEGIN SELECT RAISE(ABORT,'test failure'); END''')
        with self.assertRaises(sqlite3.IntegrityError):
            assess_investigation(incident,investigation)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0],0)

    def test_ui_cannot_assess_another_incidents_execution(self):
        incident=self.sequence(1)
        investigation=run_investigation(incident)
        other,_=self.add('other',user='bob',source='192.0.2.2')
        client=self.client()
        response=client.post(f'/incidents/{other}/assessments/{investigation}',data={'csrf_token':'test-token'})
        self.assertEqual(response.status_code,404)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0],0)

    def test_ui_authority_history_csrf_and_auto_assessment(self):
        incident=self.sequence(3)
        client=self.client()
        path=f'/incidents/{incident}'
        response=client.post(path+'/investigations',data={'csrf_token':'test-token'},follow_redirects=True)
        self.assertEqual(response.status_code,200)
        self.assertIn(b'Saved Contextual Risk',response.data)
        self.assertNotIn(b'Legacy historical data',response.data)
        self.assertIn(b'T3',response.data)
        current=current_assessment(self.db,incident)
        assessment_path=path+'/assessments/'+str(current['investigation_id'])
        self.assertEqual(client.post(assessment_path).status_code,400)
        self.assertEqual(app.test_client().post(assessment_path).status_code,302)
        self.assertEqual(client.get(assessment_path).status_code,405)
        client.get(path)
        self.assertEqual(len(assessment_history(self.db,incident)),2)
        client.post(assessment_path,data={'csrf_token':'test-token'})
        self.assertEqual(len(assessment_history(self.db,incident)),2)
        client.post(path+'/assessments/initial',data={'csrf_token':'test-token'})
        self.assertEqual(current_assessment(self.db,incident)['id'],current['id'])


if __name__ == '__main__':
    unittest.main()
