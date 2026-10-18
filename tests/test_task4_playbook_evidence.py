"""Offline, traceable Task 3 playbook observations through the Phase 6 evaluator."""

import json
import unittest

import test_investigation as fixtures
from run import app
from app.services.archive_evidence import start_group_archive_retrieval
from app.services.contextual_risk import assess_investigation
from app.services.incident_processor import process_alert
from app.services.investigation import run_investigation
from app.services.playbook_registry import FILE_PROCESS, REMOTE_ACCESS, FALLBACK


class PlaybookEvidenceTests(unittest.TestCase):
    setUp = fixtures.InvestigationTests.setUp
    tearDown = fixtures.InvestigationTests.tearDown
    client = fixtures.InvestigationTests.client

    def event(self, name, minute, groups, *, agent='001', source='192.0.2.20',
              account='analyst', event_id=None, file_path=None, process=None,
              command=None, destination=None, mitre=None, level=5):
        data = {'srcip': source, 'srcuser': account}
        if destination:
            data['dstip'] = destination
        system = {'eventID': event_id} if event_id else {}
        eventdata = {'image': process, 'targetFilename': file_path,
                     'commandLine': command, 'user': account}
        data['win'] = {'system': system, 'eventdata': {k: v for k, v in eventdata.items() if v}}
        record = {'id': name, 'timestamp': f'2026-10-09T08:{minute:02d}:00Z',
                  'agent': {'id': agent, 'name': f'LAB-{agent}'},
                  'rule': {'id': name, 'description': f'Source report {name}',
                           'level': level, 'groups': groups}, 'data': data}
        if file_path and 'syscheck' in groups:
            record['syscheck'] = {'path': file_path}
        if mitre:
            record['rule']['mitre'] = {'id': [mitre]}
        incident_id = process_alert(record)['incident_id']
        alert_id = self.db.execute('SELECT id FROM alerts WHERE wazuh_alert_id=?',
                                   (name,)).fetchone()[0]
        return incident_id, alert_id

    def assess(self, incident):
        execution = run_investigation(incident)
        assessment = assess_investigation(incident, execution)
        run = self.db.execute('SELECT * FROM investigations WHERE id=?', (execution,)).fetchone()
        row = self.db.execute('SELECT * FROM risk_assessments WHERE id=?', (assessment,)).fetchone()
        return dict(run), dict(row)

    def file_sequence(self, stage):
        incident, first = self.event('file', 0,
            ['windows', 'sysmon', 'sysmon_eid11_detections'], event_id='11',
            file_path=r'C:\Temp\sample.bin', process=r'C:\Tools\cmd.exe')
        if stage >= 2:
            self.event('process', 1, ['windows', 'sysmon', 'sysmon_eid1_detections'],
                       event_id='1', process=r'C:\Tools\cmd.exe',
                       command='cmd.exe /c whoami' if stage >= 3 else None)
        if stage >= 4:
            self.event('network', 2, ['windows', 'sysmon', 'sysmon_eid3_detections'],
                       event_id='3', process=r'C:\Tools\cmd.exe',
                       destination='198.51.100.25')
        return incident, first

    def remote_sequence(self, stage):
        incident, first = self.event('remote-fail-1', 0,
            ['windows_security', 'authentication_failed'], event_id='4625',
            destination='198.51.100.11', mitre='T1021.001')
        if stage >= 2:
            self.event('remote-fail-2', 1,
                ['windows_security', 'authentication_failed'], event_id='4625',
                destination='198.51.100.11', mitre='T1021.001')
        if stage >= 3:
            self.event('remote-success', 2,
                ['windows_security', 'authentication_success'], event_id='4624',
                destination='198.51.100.11', mitre='T1021.001')
        if stage >= 4:
            self.event('remote-later-integrity', 3, ['syscheck'],
                file_path=r'C:\Windows\System32\config\changed')
        return incident, first

    def test_file_process_t1_t2_t3_t4_from_actual_source_records(self):
        for stage, expected in ((1, 'T1'), (2, 'T2'), (3, 'T3'), (4, 'T4')):
            with self.subTest(stage=stage):
                # Each stage is a new execution over actual ingested source records.
                incident, _ = self.file_sequence(stage) if stage == 1 else (incident, None)
                if stage > 1:
                    if stage == 2:
                        self.event('process', 1, ['windows', 'sysmon', 'sysmon_eid1_detections'],
                            event_id='1', process=r'C:\Tools\cmd.exe')
                    elif stage == 3:
                        # New process observation with a reported command, not a fabricated finding.
                        self.event('command-process', 2,
                            ['windows', 'sysmon', 'sysmon_eid1_detections'], event_id='1',
                            process=r'C:\Tools\cmd.exe', command='cmd.exe /c whoami')
                    else:
                        self.event('network', 3, ['windows', 'sysmon', 'sysmon_eid3_detections'],
                            event_id='3', process=r'C:\Tools\cmd.exe', destination='198.51.100.25')
                run, result = self.assess(incident)
                self.assertEqual(run['playbook_key'], FILE_PROCESS)
                self.assertEqual(result['evidence_state'], expected)
                self.assertNotIn('confirmed malware', result['rationale'].lower())
                if expected == 'T3':
                    self.assertEqual(result['risk_level'], 'critical')
                    self.assertEqual(result['confidence'], 'low')

    def test_remote_t1_t2_t3_t4_and_no_lateral_verdict(self):
        incident, _ = self.remote_sequence(1)
        for stage, expected in ((1, 'T1'), (2, 'T2'), (3, 'T3'), (4, 'T4')):
            if stage == 2:
                self.event('remote-fail-2', 1,
                    ['windows_security', 'authentication_failed'], event_id='4625',
                    destination='198.51.100.11', mitre='T1021.001')
            elif stage == 3:
                self.event('remote-success', 2,
                    ['windows_security', 'authentication_success'], event_id='4624',
                    destination='198.51.100.11', mitre='T1021.001')
            elif stage == 4:
                self.event('remote-later-integrity', 3, ['syscheck'],
                    file_path=r'C:\Windows\System32\config\changed')
            run, result = self.assess(incident)
            self.assertEqual(run['playbook_key'], REMOTE_ACCESS)
            self.assertEqual(result['evidence_state'], expected)
            self.assertNotIn('confirmed compromise', result['rationale'].lower())

    def test_mitre_and_severity_alone_cannot_raise_state(self):
        incident, _ = self.event('mitre-only', 0, ['windows_system'], mitre='T1021.001', level=15)
        run, result = self.assess(incident)
        self.assertEqual(run['playbook_key'], REMOTE_ACCESS)
        self.assertEqual(result['evidence_state'], 'Inconclusive')
        self.assertIsNone(result['risk_level'])

    def test_conflicting_source_categories_and_event_ids_are_inconclusive(self):
        incident, _ = self.event('remote-outcome-conflict', 0,
            ['windows_security', 'authentication_failed'], event_id='4624',
            mitre='T1021.001')
        _, result = self.assess(incident)
        self.assertEqual(result['evidence_state'], 'Inconclusive')
        other, _ = self.event('file-event-conflict', 10,
            ['sysmon_eid11_detections'], event_id='1',
            file_path=r'C:\Temp\sample.bin')
        _, second = self.assess(other)
        self.assertEqual(second['evidence_state'], 'Inconclusive')

    def test_file_telemetry_missing_is_inconclusive_not_negative(self):
        incident, _ = self.event('file-without-artifact', 0,
            ['sysmon_eid11_detections'], level=15)
        run, result = self.assess(incident)
        self.assertEqual(run['playbook_key'], FILE_PROCESS)
        self.assertEqual(result['evidence_state'], 'Inconclusive')
        self.assertIsNone(result['risk_level'])

    def test_same_process_name_with_conflicting_account_cannot_be_strong(self):
        incident, _ = self.file_sequence(1)
        self.event('other-account-process', 1,
            ['windows', 'sysmon', 'sysmon_eid1_detections'], event_id='1',
            process=r'C:\Tools\cmd.exe', command='cmd.exe /c whoami', account='other')
        _, result = self.assess(incident)
        self.assertEqual(result['evidence_state'], 'T1')

    def test_t4_requires_later_linked_activity_not_just_more_mitre_ids(self):
        incident, _ = self.file_sequence(3)
        _, baseline = self.assess(incident)
        self.assertEqual(baseline['evidence_state'], 'T3')
        self.event('unrelated-later', 4, ['windows_system'], mitre='T1059.001', level=15)
        _, after = self.assess(incident)
        self.assertEqual(after['evidence_state'], 'T3')

    def test_cross_host_progression_needs_actual_distinct_agent_alert(self):
        incident, _ = self.remote_sequence(3)
        with self.db:
            self.db.execute('''INSERT INTO assets(asset_name,asset_type,asset_role,os_family,
                os_name,wazuh_agent_id,criticality,is_protected)
                VALUES('second-host','Server','Other','Other','Other','002','medium',1)''')
        other_incident, later_id = self.event('second-host-remote-success', 4,
            ['windows_security', 'authentication_success'], agent='002',
            event_id='4624', destination='198.51.100.12', mitre='T1021.001')
        self.assertNotEqual(other_incident, incident)
        # Evaluator-only fixture: Phase 4 intentionally will not auto-correlate
        # different assets. Model an explicitly linked cross-host observation.
        with self.db:
            next_ordinal = self.db.execute('SELECT MAX(ordinal)+1 FROM incident_alerts '
                'WHERE incident_id=?', (incident,)).fetchone()[0]
            self.db.execute('UPDATE incident_alerts SET incident_id=?, ordinal=?, '
                'correlation_reason=? WHERE alert_id=?',
                (incident, next_ordinal, 'fixture_explicit_cross_host_link', later_id))
            self.db.execute('DELETE FROM incidents WHERE id=?', (other_incident,))
        _, result = self.assess(incident)
        self.assertEqual(result['evidence_state'], 'T4', result['rationale'])
        self.assertIn('different reported agent', result['rationale'])
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_later_same_host_remote_success_does_not_claim_cross_host_progression(self):
        incident, _ = self.remote_sequence(3)
        self.event('another-same-host-success', 4,
            ['windows_security', 'authentication_success'], event_id='4624',
            destination='198.51.100.11', mitre='T1021.001')
        _, result = self.assess(incident)
        self.assertEqual(result['evidence_state'], 'T3')
        self.assertNotIn('different reported agent', result['rationale'])

    def test_failed_archive_retrieval_is_unavailable_not_not_observed(self):
        incident, first = self.file_sequence(1)
        with app.app_context():
            retrieval = start_group_archive_retrieval(first)
        self.assertEqual(self.db.execute('SELECT retrieval_status FROM investigation_archive_runs '
                                         'WHERE investigation_id=?', (retrieval,)).fetchone()[0], 'unavailable')
        run, result = self.assess(incident)
        finding = self.db.execute('SELECT finding_status FROM investigation_findings '
            "WHERE investigation_id=? AND finding_key='archive_coverage'", (run['id'],)).fetchone()
        self.assertEqual(finding[0], 'unavailable')
        self.assertEqual(result['evidence_state'], 'T1')

    def test_generic_fallback_is_inconclusive_and_source_refs_traceable(self):
        incident, _ = self.event('generic', 0, ['system_error'], level=15)
        run, result = self.assess(incident)
        self.assertEqual(run['playbook_key'], FALLBACK)
        self.assertEqual(result['evidence_state'], 'Inconclusive')
        self.assertIsNone(result['risk_level'])
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_incident_page_explains_state_without_internal_evaluator_keys(self):
        incident, _ = self.file_sequence(3)
        self.assess(incident)
        page = self.client().get(f'/incidents/{incident}')
        self.assertEqual(page.status_code, 200)
        html = page.get_data(as_text=True)
        self.assertIn('Evidence Strength', html)
        self.assertIn('What are CDSS evidence states?', html)
        self.assertIn('Why this evidence state?', html)
        self.assertIn('Supporting source alerts:', html)
        self.assertIn('Suspicious File / Process Investigation', html)
        self.assertNotIn('file_process_review_v1', html)

    def test_tampered_source_context_cannot_be_assessed_as_strong(self):
        incident, _ = self.file_sequence(3)
        execution = run_investigation(incident)
        with self.db:
            row = self.db.execute("SELECT id,finding_value FROM investigation_findings WHERE investigation_id=? "
                "AND finding_key='linked_alert_evidence'", (execution,)).fetchone()
            snapshot = json.loads(row['finding_value'])
            snapshot[0]['source_fields']['command_line'] = 'invented command'
            self.db.execute('UPDATE investigation_findings SET finding_value=? WHERE id=?',
                (json.dumps(snapshot), row['id']))
        assessment_id = assess_investigation(incident, execution)
        result = self.db.execute('SELECT evidence_state FROM risk_assessments WHERE id=?',
                                 (assessment_id,)).fetchone()[0]
        self.assertEqual(result, 'Inconclusive')


if __name__ == '__main__':
    unittest.main()
