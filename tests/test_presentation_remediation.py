"""Presentation-only regressions. All execution fixtures use disposable storage."""
import copy
import json
import unittest

import test_contextual_risk as fixtures
import test_soc_triage as triage_fixtures
import test_t4_causal_evidence as causal_fixtures
from run import app
from app.services.contextual_recommendations import generate_contextual_recommendations
from app.services.contextual_risk import _file_state
from app.services.dashboard_context import incident_presentation
from app.services.evidence_progression import evidence_progression
from app.services.investigation import investigation_history, _file_events
from app.services.triage import triage_page, quick_views, resolve_filters
from app.services.alert_view import GROUP_SQL, group_query_sql, _group_sql_parameters, group_context


class PresentationCorrectnessTests(unittest.TestCase):
    setUp = fixtures.ContextualRiskTests.setUp
    tearDown = fixtures.ContextualRiskTests.tearDown
    add = fixtures.ContextualRiskTests.add
    sequence = fixtures.ContextualRiskTests.sequence
    assess = fixtures.ContextualRiskTests.assess
    client = fixtures.ContextualRiskTests.client

    def saved_run(self, assessment):
        return next(run for run in investigation_history(self.db, assessment['incident_id'])
                    if run['id'] == assessment['investigation_id'])

    def test_saved_risk_survives_current_scope_and_criticality_change(self):
        incident = self.sequence(2)
        assessment = self.assess(incident)
        self.assertEqual((assessment['risk_level'], assessment['asset_criticality_snapshot']), ('high', 'critical'))
        with self.db:
            self.db.execute("UPDATE assets SET is_protected=0,criticality='low'")
        html = self.client().get(f'/incidents/{incident}').get_data(as_text=True)
        block = html.split('id="contextual-assessment"', 1)[1].split('id="contextual-guidance"', 1)[0]
        self.assertIn('<dt>Saved Contextual Risk</dt><dd>High</dd>', block)
        self.assertIn('<dt>Asset Criticality Used</dt><dd>Critical</dd>', block)
        self.assertIn('<dt>Current Risk Assessment Setting</dt><dd>Disabled</dd>', block)
        self.assertIn('Asset context has changed', block)
        self.assertNotIn('Not calculated', block)
        self.assertEqual(assessment, dict(self.db.execute('SELECT * FROM risk_assessments WHERE id=?', (assessment['id'],)).fetchone()))

    def test_enabling_current_scope_does_not_create_a_saved_risk(self):
        incident = self.sequence(2)
        with self.db:
            self.db.execute('UPDATE assets SET is_protected=0')
        assessment = self.assess(incident)
        self.assertIsNone(assessment['risk_level'])
        with self.db:
            self.db.execute('UPDATE assets SET is_protected=1')
        html = self.client().get(f'/incidents/{incident}').get_data(as_text=True)
        self.assertIn('<dt>Saved Contextual Risk</dt><dd>Unassessed</dd>', html)
        self.assertIn('<dt>Current Risk Assessment Setting</dt><dd>Enabled</dd>', html)
        self.assertEqual(assessment, dict(self.db.execute('SELECT * FROM risk_assessments WHERE id=?', (assessment['id'],)).fetchone()))

    def test_inconclusive_keeps_available_context_and_does_not_promote_it(self):
        incident, _ = self.add('generic-context', groups=['windows'], user='supporting-user', source='192.0.2.55')
        assessment = self.assess(incident)
        self.assertEqual(assessment['evidence_state'], 'Inconclusive')
        self.assertEqual(json.loads(assessment['inputs_snapshot'])['decisive_evidence_ids'], [])
        html = self.client().get(f'/incidents/{incident}').get_data(as_text=True)
        self.assertIn('192.0.2.55 (available supporting context; not decisive)', html)
        self.assertIn('supporting-user (available supporting context; not decisive)', html)
        self.assertNotIn('Network Source IP was not present', html)
        self.assertNotIn('Reported account was not present', html)
        self.assertEqual(assessment, dict(self.db.execute('SELECT * FROM risk_assessments WHERE id=?', (assessment['id'],)).fetchone()))

    def test_decisive_supporting_and_unavailable_identity_remain_distinct(self):
        snapshot = [dict(id=1, rule_description='Observed activity', username='decisive-user', source_ip=None, destination_ip=None),
                    dict(id=-2, rule_description='Supporting activity', username='supporting-user', source_ip='192.0.2.9', destination_ip=None)]
        investigation = dict(id=1, playbook_key='generic_evidence_review_v1', findings=[
            dict(finding_key='linked_alert_evidence', finding_status='observed', finding_value=json.dumps(snapshot))])
        assessment = dict(investigation_id=1, evidence_state='Inconclusive', asset_criticality_snapshot=None,
                          risk_level=None, inputs_snapshot=json.dumps(dict(decisive_evidence_ids=[1])))
        original = copy.deepcopy((snapshot, investigation, assessment))
        view = incident_presentation({}, None, snapshot, [investigation], assessment, [])
        roles = {(row['context_role'], row['label'].split(':')[0]) for row in view['evidence'] if 'context_role' in row}
        self.assertIn(('decisive', 'Reported account'), roles)
        self.assertIn(('supporting', 'Reported account'), roles)
        self.assertIn(('supporting', 'Network Source IP'), roles)
        self.assertIn(('unavailable', 'Network Destination IP was not present in the evaluated evidence.'), roles)
        self.assertEqual(original, (snapshot, investigation, assessment))

    def test_authentication_t2_and_t3_render_saved_decisive_observations(self):
        incident = self.sequence(2)
        client = self.client()
        for expected in ('T2', 'T3'):
            if expected == 'T3':
                self.add('success', minute=2, groups=['authentication_success'])
            assessment = self.assess(incident)
            self.assertEqual(assessment['evidence_state'], expected)
            run = self.saved_run(assessment)
            original = copy.deepcopy(run)
            view = evidence_progression(assessment, run)
            self.assertEqual({row['alert_id'] for row in view['decisive']}, set(json.loads(assessment['inputs_snapshot'])['decisive_evidence_ids']))
            html = client.get(f'/incidents/{incident}').get_data(as_text=True)
            progression = html.split('id="evidence-progression"', 1)[1].split('id="investigation"', 1)[0]
            self.assertIn('Authentication failure', progression)
            if expected == 'T3': self.assertIn('Authentication success', progression)
            self.assertNotIn('No structured decisive progression', html)
            self.assertEqual(run, original)

    def test_remote_access_uses_saved_remote_observations(self):
        incident = self.sequence(3)
        with self.db:
            for row in self.db.execute('SELECT id,raw_alert FROM alerts').fetchall():
                raw = json.loads(row['raw_alert'])
                groups = raw['rule']['groups'] + ['sshd']
                raw['rule']['groups'] = groups
                self.db.execute('UPDATE alerts SET raw_alert=?,rule_groups=? WHERE id=?', (json.dumps(raw), json.dumps(groups), row['id']))
        assessment = self.assess(incident)
        run = self.saved_run(assessment)
        self.assertEqual(run['playbook_key'], 'remote_access_review_v1')
        self.assertEqual(assessment['evidence_state'], 'T3')
        view = evidence_progression(assessment, run)
        self.assertEqual(len(view['decisive']), 3)
        self.assertTrue(all(row['kind'] == 'remote_authentication' for row in view['decisive']))
        html = self.client().get(f'/incidents/{incident}').get_data(as_text=True)
        self.assertIn('Remote authentication success', html)
        self.assertIn('Remote authentication failure', html)

    def test_authentication_progression_does_not_claim_process_linkage(self):
        incident = self.sequence(4)
        assessment = self.assess(incident)
        self.assertEqual(assessment['evidence_state'], 'T4')
        view = evidence_progression(assessment, self.saved_run(assessment))
        self.assertEqual(len(view['decisive']),4)
        self.assertTrue(all('process-instance' not in row['relation'] for row in view['decisive']))
        self.assertEqual({row['alert_id'] for row in view['decisive']}, set(json.loads(assessment['inputs_snapshot'])['decisive_evidence_ids']))

    def test_file_process_progression_and_business_state_unchanged(self):
        event = causal_fixtures.CausalEvidenceTests().event
        evidence = {1: event(1, 'process', 32), 2: event(2, 'file', 33), 3: event(3, 'network', 38),
                    4: event(4, 'network', 39, guid='background', pid='99')}
        findings = dict(file_process_events=dict(value=_file_events(evidence.values()), status='observed', refs=set(evidence)))
        state, decisive, _ = _file_state(findings, evidence)
        self.assertEqual((state, decisive), ('T4', [1, 2, 3]))
        assessment = dict(inputs_snapshot=json.dumps(dict(decisive_evidence_ids=decisive)))
        run = dict(playbook_key='file_process_review_v1', findings=[dict(finding_key='linked_alert_evidence', finding_value=json.dumps(list(evidence.values())))])
        view = evidence_progression(assessment, run)
        self.assertEqual([r['kind'] for r in view['decisive']], ['process', 'file', 'network'])
        self.assertEqual([r['alert_id'] for r in view['background']], [4])
        self.assertEqual(_file_state(findings, evidence)[:2], (state, decisive))

    def test_saved_ids_missing_from_snapshot_are_never_invented(self):
        assessment = dict(inputs_snapshot=json.dumps(dict(decisive_evidence_ids=[999])))
        view = evidence_progression(assessment, dict(findings=[dict(finding_key='linked_alert_evidence', finding_value='[]')]))
        self.assertEqual(view['decisive'], [])

    def test_case_order_audit_disclosure_and_history_preservation(self):
        incident = self.sequence(3)
        assessment = self.assess(incident)
        generate_contextual_recommendations(incident)
        client = self.client()
        tables = ('risk_assessments','investigations','investigation_findings','contextual_recommendations','analyst_decisions')
        before = {t: [tuple(r) for r in self.db.execute('SELECT * FROM '+t)] for t in tables}
        html = client.get(f'/incidents/{incident}').get_data(as_text=True)
        ids = ('incident-summary','contextual-assessment','contextual-guidance','analyst-decision','conclusion','investigation-details','technical-details')
        self.assertEqual(sorted(ids, key=lambda value: html.index('id="'+value+'"')), list(ids))
        primary, audit = html.split('<details class="secondary-section" id="technical-details">',1)
        self.assertNotIn('PID / ProcessGuid', primary)
        self.assertIn('View Raw Wazuh Record', audit)
        self.assertIn('View Structured Evidence', audit)
        self.assertNotIn('<details open', audit)
        self.assertEqual(before, {t: [tuple(r) for r in self.db.execute('SELECT * FROM '+t)] for t in tables})


class TriagePresentationTests(unittest.TestCase):
    setUp = triage_fixtures.SocTriageTests.setUp
    tearDown = triage_fixtures.SocTriageTests.tearDown
    client = triage_fixtures.SocTriageTests.client
    add = triage_fixtures.SocTriageTests.add
    case = triage_fixtures.SocTriageTests.case
    page = triage_fixtures.SocTriageTests.page

    def test_single_child_skips_comparison_and_preserves_membership(self):
        first = self.add('one')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM alerts')]
        client = self.client()
        html = client.get('/alerts').get_data(as_text=True)
        self.assertIn(f'href="/alerts/groups/{first}"', html)
        self.assertNotIn('/alerts/families/', html)
        response = client.get(f'/alerts/families/{first}')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.location.endswith(f'/alerts/groups/{first}'))
        self.assertEqual(before, [tuple(r) for r in self.db.execute('SELECT * FROM alerts')])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_case_alerts').fetchone()[0], 0)

    def test_multiple_children_explain_scope_without_expansion(self):
        self.add('single', level=1, path='single.dll')
        for minute in (0,1,2): self.add('repeat-'+str(minute), level=1, path='repeat.dll', minute=minute)
        items, _ = self.page()
        item = items[0]
        client = self.client()
        html = client.get('/alerts').get_data(as_text=True)
        self.assertIn('3 of 4 occurrences in the highest-priority selection', html)
        self.assertIn(f'/alerts/groups/{item["representative_alert_id"]}/investigate', html)
        self.assertIn('Compare related detections', html)
        self.assertIn('2 distinct artifacts', html)
        self.assertNotIn('artifact/context', html)
        self.assertEqual(client.get(f'/alerts/families/{item["representative_alert_id"]}').status_code,200)

    def test_primary_filters_and_visible_resolution_of_conflicts(self):
        self.add('pending', rule='pending')
        chosen = self.case(self.add('existing', rule='existing'))
        items, pagination = self.page(view='investigated', status='Needs Investigation')
        self.assertEqual(pagination['view'], 'all')
        self.assertIn('Quick view reset', pagination['filter_notice'])
        self.assertTrue(all(item['case_id'] is None for item in items))
        html = self.client().get('/alerts?view=investigated&status=Needs+Investigation').get_data(as_text=True)
        self.assertIn('Quick view reset', html)
        primary = html.split('triage-filters"',1)[1].split('<details',1)[0]
        self.assertEqual(primary.count('<label>'), 4)
        for label in ('Search','Priority','Status','Event time'): self.assertIn('<label>'+label,primary)
        self.assertIn('<summary>More filters</summary>', html)
        urgent = next(row for row in quick_views({'priority':'Low','status':'Needs Investigation'}) if row['value']=='urgent')
        self.assertNotIn('priority', urgent['args'])
        self.assertNotIn('status', urgent['args'])
        resolved, notice = resolve_filters({'view':'urgent','priority':'Low'})
        self.assertEqual(resolved['view'], 'all')
        self.assertTrue(notice)

    def test_landing_reason_compact_metrics_and_no_grouping_jargon(self):
        self.add('next')
        html = self.client().get('/').get_data(as_text=True)
        self.assertIn('primary-panel', html)
        self.assertIn('class="priority-reason"', html)
        self.assertIn('class="metric-strip"', html)
        self.assertNotIn('posture-grid', html)
        self.assertNotIn('artifact/context', html)
        self.assertNotIn('Detection families', html)
        self.assertNotIn('before banding', html)
        self.assertNotIn('Why this priority?', html)
        self.assertEqual(html.count('Last successful SIEM contact:'), 1 if 'Last successful SIEM contact:' in html else 0)
        self.assertNotIn('SIEM collection health:', html)

    def test_navigation_is_role_separated(self):
        client = self.client()
        html = client.get('/').get_data(as_text=True)
        nav = html.split('aria-label="Analyst workflow"',1)[1].split('</nav>',1)[0]
        for label in ('Triage','Investigations','Detections'):self.assertIn('>'+label+'</a>',nav)
        self.assertNotIn('Administration',html)
        with self.db:self.db.execute("UPDATE users SET role='admin'")
        html = client.get('/').get_data(as_text=True)
        self.assertIn('aria-label="Administration"',html)
        account = html.split('<details class="account-menu">',1)[1].split('</details>',1)[0]
        for path in ('/admin/assets','/admin/users','/admin/alert-retention','/admin/siem-connections'):
            self.assertNotIn(path,account)
        self.assertEqual(client.get('/admin/alert-retention').status_code,200)

    def test_shared_query_keeps_source_identity_and_case_freezing(self):
        first = self.add('first', path='a.dll')
        later = self.add('later', path='a.dll', minute=1)
        other = self.add('other', path='b.dll', minute=2)
        with app.app_context():
            params = _group_sql_parameters(self.db,60,'')
            rows = list(self.db.execute(GROUP_SQL+' SELECT id,fingerprint,group_no FROM grouped ORDER BY id',params))
            self.assertEqual(rows[0]['fingerprint'],rows[1]['fingerprint'])
            self.assertNotEqual(rows[0]['fingerprint'],rows[2]['fingerprint'])
        case = self.case(first)
        with app.app_context():
            self.assertEqual(group_context(self.db,later)['active_case_id'],case)
            self.assertEqual(group_context(self.db,other)['active_case_id'],None)
            unfrozen = list(self.db.execute(group_query_sql(preserve_cases=False)+' SELECT id,fingerprint FROM source ORDER BY id',params))
            self.assertFalse(any('existing_case' in r['fingerprint'] for r in unfrozen))
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])
