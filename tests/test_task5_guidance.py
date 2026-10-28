"""Task 5: evidence-led advisory guidance through the normal offline pipeline."""
import json
import unittest

import test_contextual_recommendations as legacy
import test_task4_playbook_evidence as fixtures
from app.services.contextual_recommendations import (
    generate_contextual_recommendations, record_analyst_decision,
)
from app.services.contextual_risk import assess_investigation
from app.services.investigation import run_investigation


class Task5GuidanceTests(unittest.TestCase):
    setUp = fixtures.PlaybookEvidenceTests.setUp
    tearDown = fixtures.PlaybookEvidenceTests.tearDown
    event = fixtures.PlaybookEvidenceTests.event
    file_sequence = fixtures.PlaybookEvidenceTests.file_sequence
    remote_sequence = fixtures.PlaybookEvidenceTests.remote_sequence

    def guidance(self, incident):
        run = run_investigation(incident)
        assessment_id = assess_investigation(incident, run)
        ids = generate_contextual_recommendations(incident)
        assessment = self.db.execute(
            'SELECT * FROM risk_assessments WHERE id=?', (assessment_id,)).fetchone()
        rows = [dict(self.db.execute(
            'SELECT * FROM contextual_recommendations WHERE id=?', (rid,)).fetchone())
            for rid in ids]
        self.assertEqual([r['priority'] for r in rows], list(range(1, len(rows)+1)))
        self.assertLessEqual(len(rows), 5)
        self.assertEqual(len({r['action_text'] for r in rows}), len(rows))
        self.assertTrue(all(r['rationale'] and 'Contextual risk:' not in r['rationale']
                            and 'Analyst review required' not in r['rationale'] for r in rows))
        linked = {r[0] for r in self.db.execute(
            'SELECT alert_id FROM incident_alerts WHERE incident_id=?', (incident,))}
        for row in rows:
            self.assertLessEqual(set(json.loads(row['evidence_snapshot'])['alert_ids']), linked)
        self.assertEqual(ids, generate_contextual_recommendations(incident))
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])
        return dict(assessment), rows

    def check_file(self, stage):
        incident, _ = self.file_sequence(stage)
        assessment, rows = self.guidance(incident)
        self.assertEqual(assessment['evidence_state'], f'T{stage}')
        keys = {r['rule_key'] for r in rows}
        self.assertIn('monitor', keys)
        self.assertEqual('consider_containment' in keys, stage == 4)
        self.assertEqual('review_command' in keys, stage >= 3)
        self.assertFalse(any('malware confirmed' in r['action_text'].lower() for r in rows))

    def test_file_t1(self): self.check_file(1)
    def test_file_t2(self): self.check_file(2)
    def test_file_t3(self): self.check_file(3)
    def test_file_t4(self): self.check_file(4)

    def check_remote(self, stage):
        incident, _ = self.remote_sequence(stage)
        assessment, rows = self.guidance(incident)
        self.assertEqual(assessment['evidence_state'], f'T{stage}')
        keys = {r['rule_key'] for r in rows}
        self.assertIn('monitor', keys)
        self.assertEqual('consider_containment' in keys, stage == 4)
        self.assertFalse(any('lateral movement confirmed' in r['action_text'].lower() for r in rows))

    def test_remote_t1(self): self.check_remote(1)
    def test_remote_t2(self): self.check_remote(2)
    def test_remote_t3(self): self.check_remote(3)
    def test_remote_t4(self): self.check_remote(4)

    def test_unavailable_archive_is_not_treated_as_negative_observation(self):
        incident, _ = self.remote_sequence(2)
        assessment, rows = self.guidance(incident)
        self.assertEqual(assessment['evidence_state'], 'T2')
        self.assertEqual(assessment['confidence'], 'low')
        finding = self.db.execute("""SELECT finding_status FROM investigation_findings
            WHERE finding_key='archive_coverage' ORDER BY id DESC LIMIT 1""").fetchone()
        self.assertEqual(finding['finding_status'], 'unavailable')
        self.assertFalse(any('no archive activity' in r['rationale'].lower() or
                             'no remote activity' in r['rationale'].lower() for r in rows))

    def test_file_and_remote_inconclusive_and_generic_fallback(self):
        cases = (
            ('file-incomplete', ['sysmon_eid11_detections'], None),
            ('remote-mapping-only', ['windows'], 'T1021.001'),
            ('generic', ['other'], None),
        )
        for name, groups, mitre in cases:
            incident, _ = self.event(name, 0, groups, mitre=mitre, level=15)
            assessment, rows = self.guidance(incident)
            self.assertEqual(assessment['evidence_state'], 'Inconclusive')
            self.assertIsNone(assessment['risk_level'])
            self.assertEqual({r['category'] for r in rows}, {'Investigation','Monitoring'})
            self.assertNotIn('consider_containment', {r['rule_key'] for r in rows})

    def test_protected_scope_wording_and_decision_no_execution(self):
        incident, _ = self.remote_sequence(2)
        with self.db:
            self.db.execute('UPDATE assets SET is_protected=0 WHERE wazuh_agent_id=?', ('001',))
        before = self.db.execute('SELECT status FROM incidents WHERE id=?', (incident,)).fetchone()[0]
        assessment, rows = self.guidance(incident)
        self.assertIsNone(assessment['risk_level'])
        self.assertNotIn('confirm_asset_scope', {row['rule_key'] for row in rows})
        self.assertFalse(any('contextual assessment scope' in row['action_text'] for row in rows))
        self.assertNotIn('obtain administrator-defined protected-asset context', rows[0]['action_text'])
        with self.db:
            user = self.db.execute("INSERT INTO users(username,password_hash,role,is_active) VALUES('task5-analyst','unused','analyst',1)").lastrowid
        record_analyst_decision(incident, assessment['id'], rows[0]['id'], user, 'accept', 'Review only')
        self.assertEqual(self.db.execute('SELECT status FROM incidents WHERE id=?', (incident,)).fetchone()[0], before)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM analyst_decisions').fetchone()[0], 1)

    def test_v1_history_not_duplicated_in_current_ui(self):
        incident, _ = self.remote_sequence(2)
        run = run_investigation(incident)
        assessment_id = assess_investigation(incident, run)
        with self.db:
            self.db.execute('''INSERT INTO contextual_recommendations
                (incident_id,assessment_id,rule_key,category,priority,action_text,source_reference,
                 rationale,evidence_snapshot,methodology_version)
                VALUES(?,?,?, ?,1,?,?,?,?,'cdss-guidance-v1')''',
                (incident,assessment_id,'old','Investigation','Old guidance','historical',
                 'Historical only','{}'))
        generate_contextual_recommendations(incident)
        from run import app
        with self.db:
            uid = self.db.execute("INSERT INTO users(username,password_hash,role) VALUES('task5-ui','unused','analyst')").lastrowid
        client = app.test_client()
        with client.session_transaction() as session:
            session['user_id'] = uid
        response = client.get(f'/incidents/{incident}')
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(b'Old guidance', response.data.split(b'id="contextual-guidance"')[1].split(b'id="analyst-decision"')[0])


class AuthenticationTask5Tests(unittest.TestCase):
    """Reuse original auth fixtures without duplicating the source-event builder."""
    setUp = legacy.ContextualRecommendationTests.setUp
    tearDown = legacy.ContextualRecommendationTests.tearDown
    sequence = legacy.ContextualRecommendationTests.sequence
    add = legacy.ContextualRecommendationTests.add
    assess = legacy.ContextualRecommendationTests.assess
    generate = legacy.ContextualRecommendationTests.generate

    def test_auth_t1_to_t4_concise_progression(self):
        incident = self.sequence(1)
        expected = {'T1':'review_authentication', 'T2':'review_authentication',
                    'T3':'validate_success', 'T4':'review_post_activity'}
        for stage in range(1, 5):
            if stage == 2:
                self.add('task5-fail-two', minute=1)
            elif stage == 3:
                self.add('task5-success', minute=2, groups=['authentication_success'])
            elif stage == 4:
                self.add('task5-integrity', minute=3, groups=['syscheck'])
            assessment = self.assess(incident)
            rows = self.generate(incident)
            self.assertEqual(assessment['evidence_state'], f'T{stage}')
            self.assertIn(expected[f'T{stage}'], {r['rule_key'] for r in rows})
            self.assertLessEqual(len(rows), 5)
            self.assertEqual('consider_containment' in {r['rule_key'] for r in rows}, stage == 4)

