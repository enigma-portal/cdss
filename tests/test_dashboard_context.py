"""Phase 8 real-data presentation, chronology, current methodology and safety."""
import json
import unittest

import test_contextual_risk as fixtures
from run import app
from app.services.dashboard_context import (
    overview_data, list_data, incident_evidence, incident_presentation,
    recommendation_presentation,
)
from app.services.contextual_risk import create_initial_assessment
from app.services.contextual_recommendations import generate_contextual_recommendations,record_analyst_decision


class ContextualDashboardTests(unittest.TestCase):
    setUp=fixtures.ContextualRiskTests.setUp
    tearDown=fixtures.ContextualRiskTests.tearDown
    add=fixtures.ContextualRiskTests.add
    sequence=fixtures.ContextualRiskTests.sequence
    assess=fixtures.ContextualRiskTests.assess
    client=fixtures.ContextualRiskTests.client

    def test_saved_assessment_uses_its_own_findings_and_specific_observations(self):
        assessed = {'id': 10, 'playbook_key': 'file_process_review_v1', 'findings': [
            {'finding_key': 'asset_context', 'finding_status': 'observed',
             'finding_value': '{"id": 1}'},
            {'finding_key': 'file_process_events', 'finding_status': 'observed',
             'finding_value': json.dumps([{'alert_id': 1, 'kind': 'file', 'file_path': 'C:/Temp/sample.ps1'}])},
        ]}
        newer = {'id': 11, 'playbook_key': 'generic_evidence_review_v1', 'findings': [
            {'finding_key': 'no_specific_playbook', 'finding_status': 'observed',
             'finding_value': '{}'},
        ]}
        contextual = {'investigation_id': 10, 'evidence_state': 'T1',
                      'asset_criticality_snapshot': None, 'risk_level': None,
                      'inputs_snapshot': json.dumps({'decisive_evidence_ids': [1], 'evidence_reason':
                          'One file/process observation is traceable, without related corroboration.'})}
        timeline = [{'id': 1, 'rule_description': 'File alert', 'source_ip': None,
                     'username': None}]
        presentation = incident_presentation({'rule_description': 'File alert'}, None,
                                             timeline, [newer, assessed], contextual, [])
        labels = [item['label'] for item in presentation['evidence']]
        self.assertEqual(presentation['latest_investigation']['id'], 10)
        self.assertIn('File alert: C:/Temp/sample.ps1', labels)
        self.assertNotIn('Configured asset context', labels)
        self.assertNotIn('Structured file and process observations', labels)
        self.assertNotIn('Generic evidence review', presentation['summary'])
        self.assertIn('1 structured file/process observation is', presentation['evidence_reason'])
        recommendation = {'methodology_version': 'cdss-guidance-v2',
                          'rule_key': 'review_file_origin',
                          'action_text': 'Validate the reported file or process origin.',
                          'rationale': 'One structured file/process observation is recorded.'}
        displayed = recommendation_presentation(recommendation, None, timeline,
                                                contextual, assessed)
        self.assertIn('1 structured file/process observation is', displayed['display_why'])
        self.assertEqual(recommendation['rationale'],
                         'One structured file/process observation is recorded.')

    def test_distribution_uses_only_latest_contextual_assessment(self):
        incident=self.sequence(3)
        self.assess(incident)
        self.assertEqual(overview_data()['risks']['critical'],1)
        with self.db:
            self.db.execute("UPDATE assets SET criticality='low'")
            self.db.execute("UPDATE incidents SET severity_label='critical'")
            self.db.execute('UPDATE risk_scores SET final_risk_score=10')
        self.assess(incident)
        overview=overview_data()
        self.assertEqual(overview['total'],1)
        self.assertEqual(overview['assessed'],1)
        self.assertEqual(overview['risks'],dict(critical=0,high=0,medium=1,low=0,unassessed=0))
        self.assertEqual(sum(overview['confidences'].values()),1)
        self.assertEqual(list_data({'severity':'critical'})[2]['total'],0)
        self.assertEqual(list_data({'severity':'medium'})[2]['total'],1)

    def test_no_assessment_and_initial_only_are_unassessed(self):
        incident=self.sequence(1)
        create_initial_assessment(incident)
        self.assertEqual(overview_data()['assessed'],0)
        # Historical auto-cases without analyst investigation are retained for
        # audit, but no longer count as active investigation cases.
        self.assertEqual(overview_data()['risks']['unassessed'],0)
        client=self.client()
        html=client.get('/incidents').data
        self.assertNotIn(f'/incidents/{incident}'.encode(),html)
        self.assertNotIn(b'/ 10',html)
        detail=client.get(f'/incidents/{incident}').data
        self.assertIn(b'Not Yet Assessed',detail)
        self.assertIn(b'No investigation has been run',detail)

    def test_inconclusive_assessed_but_unassessed_risk(self):
        incident,_=self.add('success',groups=['authentication_success'])
        self.assess(incident)
        result=overview_data()
        self.assertEqual(result['assessed'],1)
        self.assertEqual(result['risks']['unassessed'],1)
        self.assertEqual(list_data({'evidence':'Inconclusive'})[2]['total'],1)

    def test_assets_and_criticality_snapshot_separate(self):
        incident=self.sequence(2)
        self.assess(incident)
        with self.db:
            self.db.execute("UPDATE assets SET criticality='low',asset_name='Configured asset'")
        client=self.client()
        response=client.get(f'/incidents/{incident}')
        self.assertIn(b'Configured asset',response.data)
        self.assertIn(b'<dt>Criticality</dt>',response.data)
        self.assertIn(b'Asset Criticality Used',response.data)
        self.assertIn(b'Asset context has changed',response.data)
        rows=list_data({'criticality':'low'})[1]
        self.assertEqual(rows[0]['criticality'],'low')
        self.assertEqual(rows[0]['asset_criticality_snapshot'],'critical')
        self.assertEqual(rows[0]['risk_level'],'high')

    def test_unmapped_asset_not_replaced_with_agent_name(self):
        incident,_=self.add('unmapped',agent='999')
        self.assess(incident)
        response=self.client().get(f'/incidents/{incident}')
        self.assertIn(b'Configured CDSS Asset',response.data)
        self.assertIn(b'Not mapped',response.data)
        self.assertEqual(list_data({'criticality':'unmapped'})[2]['total'],1)

    def test_timeline_all_members_utc_order_not_insertion(self):
        incident,late=self.add('late',minute=5)
        _,early=self.add('early',minute=1)
        _,middle=self.add('middle',minute=3)
        with self.db:
            self.db.execute("UPDATE alerts SET event_timestamp='2026-09-26T17:03:00+05:00' WHERE id=?",(middle,))
        self.assertEqual([a['id'] for a in incident_evidence(self.db,incident)],[early,middle,late])
        html=self.client().get(f'/incidents/{incident}').data
        self.assertLess(html.index(f'id="alert-{early}"'.encode()),html.index(f'id="alert-{middle}"'.encode()))
        self.assertLess(html.index(f'id="alert-{middle}"'.encode()),html.index(f'id="alert-{late}"'.encode()))
        self.assertIn(b'Correlation</dt>',html)
        self.assertIn(b'not a confirmed attack chain',html)
        self.assertIn(b'Wazuh Detection Level',html)

    def test_unknown_timestamp_last_no_seed_fallback(self):
        incident,first=self.add('unknown')
        _,second=self.add('known',minute=2)
        with self.db:
            self.db.execute("UPDATE alerts SET event_timestamp='unknown' WHERE id=?",(first,))
        rows=incident_evidence(self.db,incident)
        self.assertEqual([r['id'] for r in rows],[second,first])
        self.assertFalse(rows[-1]['time_known'])
        with self.db:
            self.db.execute('DELETE FROM incident_alerts WHERE incident_id=?',(incident,))
        self.assertEqual(incident_evidence(self.db,incident),[])

    def test_multiple_mitre_and_per_alert_provenance(self):
        incident,_=self.add('mapped',mitre=['T1110','T1059.001'])
        _,unmapped=self.add('unmapped',minute=1)
        self.assess(incident)
        html=self.client().get(f'/incidents/{incident}').data
        self.assertIn(b'T1110',html)
        self.assertIn(b'T1059.001',html)
        self.assertIn(b'Mapping provenance',html)
        self.assertIn(b'Wazuh alert mapped:',html)
        self.assertIn(b'Tactic',html)
        self.assertIn(b'Not Mapped',html)
        # Detailed ATT&CK context stays in the incident, not the triage table.
        self.assertNotIn(b'T1110',self.client_list_without_new_user(incident))
        self.assertEqual(list_data({'q':'T1110'})[2]['total'],1)

    def client_list_without_new_user(self,incident):
        # Reuse a fresh Flask session for the existing authenticated fixture user.
        client=app.test_client()
        uid=self.db.execute("SELECT id FROM users WHERE username='analyst-test'").fetchone()[0]
        with client.session_transaction() as session:
            session['user_id']=uid
        return client.get('/incidents').data

    def test_investigation_rationale_guidance_decisions_and_history(self):
        incident=self.sequence(3)
        assessment=self.assess(incident)
        ids=generate_contextual_recommendations(incident)
        client=self.client()
        uid=self.db.execute("SELECT id FROM users WHERE username='analyst-test'").fetchone()[0]
        record_analyst_decision(incident,assessment['id'],ids[0],uid,'accept','First decision')
        record_analyst_decision(incident,assessment['id'],ids[0],uid,'further_investigation_required','<script>unsafe()</script>')
        html=client.get(f'/incidents/{incident}').data
        for expected in (b'Key Findings',b'Investigation Approach',b'Recommended Follow-up',
                         b'Decision History',b'First decision',b'&lt;script&gt;unsafe()',b'Audit Summary'):
            self.assertIn(expected,html)
        self.assertNotIn(b'Legacy numeric score',html)
        self.assertNotIn(b'<script>unsafe()</script>',html)
        self.assertEqual(list_data({'decision':'further_investigation_required'})[2]['total'],1)
        self.assertEqual(overview_data()['attention'],1)
        self.assess(incident)
        self.assertEqual(list_data({'decision':'pending'})[2]['total'],1)

    def test_fallback_and_unavailable_findings_distinct(self):
        incident,_=self.add('generic',groups=['windows'],agent='missing',source=None,user=None)
        self.assess(incident)
        html=self.client().get(f'/incidents/{incident}').data
        self.assertIn(b'No dedicated playbook matched',html)
        self.assertIn(b'Network Source IP was not present in the evaluated evidence.',html)
        self.assertIn(b'Reported account was not present in the evaluated evidence.',html)
        self.assertIn(b'Configured asset context',html)
        self.assertIn(b'unavailable',html)
        self.assertIn(b'Inconclusive',html)

    def test_raw_secrets_not_exposed_and_source_text_escaped(self):
        incident,aid=self.add('untrusted')
        with self.db:
            self.db.execute('UPDATE alerts SET raw_alert=?,rule_description=? WHERE id=?',
                (json.dumps({'id':'safe-id','password':'DO-NOT-DISPLAY',
                    'rule':{'id':'42','description':'<script>raw()</script>','groups':['syscheck'],
                            'token':'DO-NOT-DISPLAY'},
                    'data':{'srcip':'192.0.2.1','password':'DO-NOT-DISPLAY'}}),
                 '<script>source()</script>',aid))
        html=self.client().get(f'/incidents/{incident}').data
        self.assertNotIn(b'DO-NOT-DISPLAY',html)
        self.assertNotIn(b'<script>raw()</script>',html)
        self.assertNotIn(b'<script>source()</script>',html)
        self.assertIn(b'&lt;script&gt;source()',html)
        self.assertIn(b'safe-id',html)
        self.assertIn(b'View Raw Wazuh Record',html)

    def test_filter_validation_search_all_related_alerts_and_status(self):
        incident=self.sequence(2)
        self.add('second-search-marker',minute=3)
        self.assess(incident)
        self.assertEqual(list_data({'q':'second-search-marker'})[2]['total'],1)
        self.assertEqual(list_data({'status':'closed'})[2]['total'],0)
        self.assertEqual(list_data({'status':'invalid','severity':'invalid','page':'bad'})[2]['page'],1)
        self.assertEqual(list_data({'view':'active'})[2]['total'],1)

    def test_presentation_read_only_and_no_fake_metrics(self):
        incident=self.sequence(3)
        self.assess(incident)
        client=self.client()
        tables=('incidents','risk_assessments','investigations','investigation_findings','contextual_recommendations','analyst_decisions','risk_scores')
        before={t:[tuple(r) for r in self.db.execute('SELECT * FROM '+t+' ORDER BY id')] for t in tables}
        for path in ('/','/incidents',f'/incidents/{incident}'):
            self.assertEqual(client.get(path).status_code,200)
        after={t:[tuple(r) for r in self.db.execute('SELECT * FROM '+t+' ORDER BY id')] for t in tables}
        self.assertEqual(before,after)
        html=client.get('/').data
        for invented in (b'Observed posture',b'MTTR',b'/100',b'analyst time saved'):
            self.assertNotIn(invented,html)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_anonymous_routes_and_csrf_protected_actions(self):
        incident=self.sequence(1)
        for path in ('/','/incidents',f'/incidents/{incident}'):
            self.assertEqual(app.test_client().get(path).status_code,302)
        client=self.client()
        self.assertEqual(client.post(f'/incidents/{incident}/investigations').status_code,400)
        self.assertEqual(client.post(f'/incidents/{incident}/analyst-decisions').status_code,400)

    def test_partial_review_and_per_recommendation_latest_decisions(self):
        incident=self.sequence(3)
        assessment=self.assess(incident)
        ids=generate_contextual_recommendations(incident)
        self.client()
        uid=self.db.execute("SELECT id FROM users WHERE username='analyst-test'").fetchone()[0]
        self.assertGreater(len(ids),1)
        record_analyst_decision(incident,assessment['id'],ids[0],uid,'accept','')
        self.assertEqual(overview_data()['attention'],1)
        self.assertEqual(list_data({})[1][0]['pending_recommendations'],len(ids)-1)
        record_analyst_decision(incident,assessment['id'],ids[0],uid,'further_investigation_required','')
        for rid in ids[1:]:
            record_analyst_decision(incident,assessment['id'],rid,uid,'accept','')
        self.assertEqual(overview_data()['attention'],1)
        self.assertEqual(overview_data()['further_review'],1)
        self.assertEqual(list_data({'view':'further_review'})[2]['total'],1)
        record_analyst_decision(incident,assessment['id'],ids[0],uid,'reject','')
        self.assertEqual(overview_data()['attention'],0)
        self.assertEqual(overview_data()['further_review'],0)
        self.assess(incident)
        self.assertEqual(overview_data()['attention'],1)

    def test_case_level_decision_persists_and_renders_immediately(self):
        incident=self.sequence(3)
        assessment=self.assess(incident)
        generate_contextual_recommendations(incident)
        client=self.client()
        page=client.get(f'/incidents/{incident}').data.decode()
        section=page.split('id="analyst-decision"',1)[1].split('id="technical-details"',1)[0]
        self.assertEqual(section.count('name="decision"'),1)
        self.assertNotIn('name="recommendation_id"',section)
        before=self.db.execute('SELECT COUNT(*) FROM risk_assessments WHERE incident_id=?',(incident,)).fetchone()[0]
        for choice,reason in (('further_investigation_required','Check account owner'),
                              ('accept','Approved response plan')):
            response=client.post(f'/incidents/{incident}/analyst-decisions',data={
                'csrf_token':'test-token','assessment_id':str(assessment['id']),
                'decision':choice,'comments':reason},follow_redirects=True)
            self.assertEqual(response.status_code,200)
            self.assertIn(reason.encode(),response.data)
            self.assertIn(b'Current Analyst Decision',response.data)
        rows=list(self.db.execute('''SELECT decision,comments,analyst_name_snapshot,
            incident_recommendation_id FROM analyst_decisions WHERE incident_id=? ORDER BY id''',(incident,)))
        self.assertEqual([(r['decision'],r['comments']) for r in rows],
                         [('further_investigation_required','Check account owner'),
                          ('accept','Approved response plan')])
        self.assertTrue(all(r['incident_recommendation_id'] is None and
                            r['analyst_name_snapshot']=='analyst-test' for r in rows))
        self.assertEqual(overview_data()['attention'],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments WHERE incident_id=?',
                                         (incident,)).fetchone()[0],before)

    def test_unmapped_agent_002_explicit_context_and_no_inventory_mutation(self):
        incident, alert_id = self.add('unmapped-002', agent='002')
        before = [tuple(r) for r in self.db.execute('SELECT * FROM assets ORDER BY id')]
        assessment = self.assess(incident)
        self.assertIsNone(assessment['risk_level'])
        self.assertIsNone(assessment['asset_criticality_snapshot'])
        client = self.client()
        for route in (f'/alerts/{alert_id}', f'/alerts/groups/{alert_id}', f'/incidents/{incident}'):
            response = client.get(route)
            self.assertEqual(response.status_code, 200)
            html = response.get_data(as_text=True)
            labels = (('Criticality', 'Saved Contextual Risk', 'Current Risk Assessment Setting',
                       'Unassessed because no mapped asset/criticality is available.')
                      if route.startswith('/incidents/') else
                      ('Asset criticality', 'Contextual assessment scope',
                       'Unassessed because no mapped asset/criticality/assessment scope is available.'))
            for text in ('Wazuh Agent ID', '002', 'Not mapped', 'Unavailable') + labels:
                self.assertIn(text, html)
        self.assertEqual(before, [tuple(r) for r in self.db.execute('SELECT * FROM assets ORDER BY id')])

    def test_imported_source_claim_requires_saved_matching_hash(self):
        incident=self.sequence(1)
        assessment=self.assess(incident)
        client=self.client()
        verified=client.get(f'/incidents/{incident}').data.decode()
        self.assertIn('Source artifact:',verified)
        primary, audit = verified.split('<details class="secondary-section" id="technical-details">', 1)
        saved_hash = self.db.execute('SELECT playbook_import_hash FROM investigations WHERE id=?',
                                    (assessment['investigation_id'],)).fetchone()[0]
        self.assertNotIn(saved_hash, primary)
        self.assertIn(saved_hash, audit)
        self.assertIn('Imported playbook SHA-256', audit)
        actions = primary.split('id="contextual-guidance"', 1)[1].split('id="analyst-decision"', 1)[0]
        self.assertNotIn('CDSS Contextual Risk:', actions)
        self.assertNotIn('Assessment Confidence:', actions)
        with self.db:
            self.db.execute('UPDATE investigations SET playbook_import_hash=NULL WHERE id=?',
                            (assessment['investigation_id'],))
        unverified=client.get(f'/incidents/{incident}').data.decode()
        self.assertNotIn('Source artifact:',unverified)
        self.assertIn('Imported artifact provenance was not verified',unverified)

    def test_priority_queue_risk_before_recency_and_card_filters(self):
        critical=self.sequence(3)
        self.assess(critical)
        low,_=self.add('newer-limited',minute=10,user='other')
        self.assess(low)
        self.assertEqual(overview_data()['queue'][0]['id'],critical)
        self.assertEqual(overview_data()['active_high'],list_data({'view':'active_high'})[2]['total'])
        with self.db:
            self.db.execute("UPDATE incidents SET status='closed' WHERE id=?",(critical,))
        self.assertEqual(overview_data()['active_high'],0)
        self.assertEqual(list_data({'view':'active_high'})[2]['total'],0)

    def test_source_groups_visible_and_current_guidance_not_duplicated(self):
        incident=self.sequence(3)
        self.assess(incident)
        generate_contextual_recommendations(incident)
        html=self.client().get(f'/incidents/{incident}').data.decode()
        self.assertIn('authentication_failed',html)
        current=self.db.execute('SELECT action_text FROM contextual_recommendations WHERE incident_id=?',(incident,)).fetchall()
        from markupsafe import escape
        actions=html.split('id="contextual-guidance"',1)[1].split('id="analyst-decision"',1)[0]
        for row in current:
            self.assertEqual(actions.count(str(escape(row['action_text']))),1)
        self.assertIn('<details class="secondary-section" id="technical-details">',html)
        self.assertLess(html.index('id="investigation"'),html.index('id="related-evidence"'))

    def test_non_ascii_csrf_rejected_without_internal_error(self):
        client=self.client()
        client.get('/')
        self.assertEqual(client.post('/logout',data={'csrf_token':'\u2603'}).status_code,400)

    def test_responsive_navigation_and_table_styles_are_served(self):
        # Guard the wrapping rules responsible for the observed narrow-window bug.
        css=app.test_client().get('/static/css/contextual-dashboard.css').data
        self.assertIn(b'.primary-nav { min-width:0; width:100%; flex-wrap:wrap;',css)
        self.assertIn(b'white-space:normal',css)
        self.assertIn(b'content:attr(data-label)',css)
        self.assertNotIn(b'min-width: 1080px',css)

    def test_changed_evidence_and_asset_are_not_silently_current(self):
        from app.services.dashboard_context import assessment_notices
        incident=self.sequence(2)
        assessment=self.assess(incident)
        asset=self.db.execute('SELECT * FROM assets').fetchone()
        self.assertEqual(assessment_notices(self.db,incident,assessment,asset),[])
        self.add('later-success',minute=3,groups=['authentication_success'])
        with self.db:
            self.db.execute("UPDATE assets SET criticality='low'")
        asset=self.db.execute('SELECT * FROM assets').fetchone()
        notices=assessment_notices(self.db,incident,assessment,asset)
        self.assertEqual(len(notices),2)
        html=self.client().get(f'/incidents/{incident}').data
        self.assertIn(b'Related alerts have changed',html)
        self.assertIn(b'Asset context has changed',html)
        saved=self.db.execute('SELECT * FROM risk_assessments WHERE id=?',(assessment['id'],)).fetchone()
        self.assertEqual(saved['risk_level'],assessment['risk_level'])
        self.assertEqual(saved['asset_criticality_snapshot'],'critical')

    def test_human_first_detail_keeps_stale_snapshot_and_technical_data_separate(self):
        incident,_=self.add('file-observation',groups=['windows'],agent='missing',source=None,user=None,
                            mitre=['T1110','T1059.001'])
        assessment=self.assess(incident)
        self.assertEqual(assessment['evidence_state'],'Inconclusive')
        self.assertIsNone(assessment['asset_criticality_snapshot'])
        generate_contextual_recommendations(incident)
        configured=self.db.execute('SELECT id FROM assets LIMIT 1').fetchone()[0]
        with self.db:
            self.db.execute("UPDATE assets SET asset_name='Current configured asset',criticality='medium' WHERE id=?",(configured,))
            self.db.execute('UPDATE incidents SET asset_id=? WHERE id=?',(configured,incident))
        html=self.client().get(f'/incidents/{incident}').data.decode()
        primary,audit=html.split('<details class="secondary-section" id="technical-details">',1)
        sections = ('incident-summary','contextual-assessment','contextual-guidance','analyst-decision',
                    'conclusion','investigation-details')
        self.assertEqual(sorted(sections, key=lambda value: primary.index('id="'+value+'"')), list(sections))
        for heading in ('Incident Summary','Supporting Evidence','Key Findings',
                        'Evidence State','Saved Contextual Risk',
                        'Recommended Follow-up','Analyst Decision'):
            self.assertIn(heading,primary)
        self.assertIn('Current configured asset',primary)
        self.assertIn('<dt>Criticality</dt>',primary)
        self.assertIn('Asset Criticality Used',primary)
        self.assertIn('Unavailable in saved assessment',primary)
        self.assertEqual(primary.count('Asset context has changed'),1)
        self.assertIn('Re-run Investigation &amp; Reassess',primary)
        self.assertIn('Generic Evidence Review',primary)
        self.assertIn('Inconclusive',primary)
        self.assertIn('Unassessed',primary)
        self.assertEqual(primary.count('T1110'),0)
        self.assertIn('T1110',audit)
        self.assertEqual(primary.count('T1059.001'),0)
        self.assertIn('T1059.001',audit)
        for internal in ('Execution #','generic_evidence_review_v1','seed_migrated',
                         'cdss-contextual-v1','cdss-guidance-v1','40% Wazuh','Legacy numeric score'):
            self.assertNotIn(internal,primary)
        self.assertTrue(audit.lstrip().startswith('<summary>Technical / Audit Details</summary>'))
        self.assertIn('Assessment History',audit)
        self.assertIn('View Raw Wazuh Record',audit)
        self.assertIn('View Structured Evidence',audit)
        self.assertNotIn('Legacy numeric score',html)
        self.assertNotIn('Record preliminary triage only',html)

    def test_audit_is_concise_and_collapsed_without_legacy_values(self):
        import re
        incident=self.sequence(3)
        self.assess(incident)
        generate_contextual_recommendations(incident)
        html=self.client().get(f'/incidents/{incident}').data.decode()
        audit=html.split('<details class="secondary-section" id="technical-details">',1)[1]
        summary=audit.split('<details>',1)[0]
        for label in ('Source Wazuh alert ID','Wazuh rule ID','Wazuh Detection Level',
                      'CDSS case / alert IDs','Wazuh rule groups','Correlation',
                      'Initial priority model','Assessment model','Saved execution'):
            self.assertIn(label,summary)
        self.assertNotIn('<dt>Configured asset</dt>',summary)
        self.assertNotIn('<dt>Latest analyst decision</dt>',summary)
        self.assertGreaterEqual(len(re.findall(r'<details\b[^>]*>',audit)),6)
        self.assertNotRegex(audit,r'<details\b[^>]*\bopen\b')
        self.assertLess(audit.index('View Raw Wazuh Record'),audit.index('<pre'))
        self.assertLess(audit.index('View Structured Evidence'),audit.rindex('<pre'))
        for internal in ('generic_evidence_review_v1','linked_alert_evidence','asset_context',
                         'mitre_context','no_specific_playbook','cdss-contextual-v1',
                         'cdss-guidance-v1','seed_migrated','source_reference',
                         'ordinal','catalogue_source'):
            self.assertNotIn(internal,summary)
        for legacy in ('Legacy numeric score','Historical weights','Legacy classification',
                       'Legacy historical data','Recommendation history and references'):
            self.assertNotIn(legacy,html)

    def test_each_current_recommendation_has_one_title_and_one_reason(self):
        import re
        incident=self.sequence(3)
        self.assess(incident)
        ids=generate_contextual_recommendations(incident)
        html=self.client().get(f'/incidents/{incident}').data.decode()
        actions=html.split('id="contextual-guidance"',1)[1].split('id="analyst-decision"',1)[0]
        items=re.findall(r'<li><strong>(.*?)</strong>(.*?)</li>',actions,re.S)
        self.assertEqual(len(items),len(ids))
        self.assertEqual(actions.count('<strong>Why this action?</strong>'),len(ids))
        for title,body in items:
            self.assertTrue(title.strip())
            self.assertEqual(body.count('<strong>Why this action?</strong>'),1)
            self.assertRegex(body,r'<p class="metadata"><strong>Why this action\?</strong>[^<]+</p>')

    def test_recommendation_reasons_use_current_context_without_changing_saved_guidance(self):
        incident,_=self.add('generic-evidence',groups=['windows'],source=None,user=None)
        with self.db:
            self.db.execute("UPDATE assets SET criticality='medium',is_protected=0 WHERE wazuh_agent_id='001'")
        self.assess(incident)
        generate_contextual_recommendations(incident)
        saved=[tuple(row) for row in self.db.execute('''SELECT id,rule_key,action_text,rationale
            FROM contextual_recommendations WHERE incident_id=? ORDER BY priority''',(incident,))]
        html=self.client().get(f'/incidents/{incident}').data.decode()
        actions=html.split('id="contextual-guidance"',1)[1].split('id="analyst-decision"',1)[0]
        # Risk and confidence belong to the assessment section, not a duplicate
        # summary above the recommendations.
        self.assertNotIn('CDSS Contextual Risk:', actions)
        self.assertNotIn('Assessment Confidence:', actions)
        self.assertIn('<dt>Saved Contextual Risk</dt>', html)
        self.assertIn('<dt>Current Risk Assessment Setting</dt><dd>Disabled</dd>', html)
        self.assertIn('<dt>Assessment Confidence</dt>', html)
        self.assertNotIn('Confirm whether this asset belongs in contextual assessment scope',actions)
        self.assertNotIn('outside contextual assessment scope',actions)
        self.assertIn('Not calculated — Risk Assessment disabled for this asset.',html)
        self.assertIn('No dedicated playbook matched',actions)
        self.assertIn('Current evidence does not support a specific response action',actions)
        self.assertNotIn('administrator-defined protected-asset context',actions)
        self.assertNotIn('Analyst review required.',actions)
        self.assertNotIn('confidence: low',actions)
        self.assertEqual(saved,[tuple(row) for row in self.db.execute('''SELECT id,rule_key,action_text,rationale
            FROM contextual_recommendations WHERE incident_id=? ORDER BY priority''',(incident,))])

    def test_unmapped_asset_guidance_does_not_claim_protected_context(self):
        incident,_=self.add('unmapped-generic',groups=['windows'],agent='unmapped',source=None,user=None)
        self.assess(incident)
        generate_contextual_recommendations(incident)
        actions=self.client().get(f'/incidents/{incident}').data.decode().split('id="contextual-guidance"',1)[1].split('id="analyst-decision"',1)[0]
        self.assertIn('Identify the affected asset and obtain missing source evidence',actions)
        self.assertIn('No configured asset is linked',actions)
        self.assertNotIn('administrator-defined protected-asset context',actions)


if __name__=='__main__':
    unittest.main()
