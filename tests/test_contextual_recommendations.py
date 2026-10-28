"""Phase 7 advisory-only guidance, explicit human decisions and audit history."""
import json
import sqlite3
import unittest
from unittest.mock import patch

import test_contextual_risk as fixtures
from run import app
from app.database.phase7 import migrate_contextual_guidance
from app.services.investigation import run_investigation
from app.services.contextual_risk import assess_investigation
from app.services.contextual_recommendations import (
    generate_contextual_recommendations, record_analyst_decision,
    recommendation_history, decision_history, VERSION,
)


class ContextualRecommendationTests(unittest.TestCase):
    setUp=fixtures.ContextualRiskTests.setUp
    tearDown=fixtures.ContextualRiskTests.tearDown
    add=fixtures.ContextualRiskTests.add
    sequence=fixtures.ContextualRiskTests.sequence
    assess=fixtures.ContextualRiskTests.assess
    client=fixtures.ContextualRiskTests.client

    def generate(self,incident):
        generate_contextual_recommendations(incident)
        rows=recommendation_history(self.db,incident)
        latest=max(r['assessment_id'] for r in rows)
        return [r for r in rows if r['assessment_id']==latest]

    def setup_guidance(self,stage=2):
        incident=self.sequence(stage)
        assessment=self.assess(incident)
        return incident,assessment,self.generate(incident)

    def user(self,role='analyst',active=1):
        with self.db:
            return self.db.execute('INSERT INTO users(username,password_hash,role,is_active) VALUES(?,?,?,?)',
                ('test-'+role,'unused',role,active)).lastrowid

    def unchanged_snapshot(self):
        return {t:[tuple(r) for r in self.db.execute('SELECT * FROM '+t+' ORDER BY rowid')]
                for t in ('risk_assessments','risk_scores','incident_recommendations','incidents','alerts',
                          'knowledge_base','recommendations','siem_connections')}

    def test_additive_schema_and_source_distinction(self):
        incident,assessment,items=self.setup_guidance()
        before=self.unchanged_snapshot()
        with self.db:
            migrate_contextual_guidance(self.db)
            migrate_contextual_guidance(self.db)
        self.assertEqual(before,self.unchanged_snapshot())
        self.assertTrue(all(r['methodology_version']==VERSION for r in items))
        self.assertTrue(all(r['source_reference'].startswith('CDSS project guidance /') for r in items))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM analyst_decisions').fetchone()[0],0)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])
        with self.assertRaises(sqlite3.IntegrityError),self.db:
            self.db.execute("UPDATE contextual_recommendations SET category='automatic_response'")

    def test_t1_only_investigation_monitoring(self):
        _,_,items=self.setup_guidance(1)
        self.assertEqual({r['category'] for r in items},{'Investigation','Monitoring'})
        self.assertNotIn('validate_success',{r['rule_key'] for r in items})

    def test_t2_failures_no_containment_or_remediation(self):
        _,_,items=self.setup_guidance(2)
        self.assertEqual({r['category'] for r in items},{'Investigation','Monitoring'})
        self.assertIn('review_authentication',{r['rule_key'] for r in items})
        self.assertNotIn('repair_confirmed_changes',{r['rule_key'] for r in items})

    def test_t3_authorization_and_related_activity_not_compromise(self):
        _,_,items=self.setup_guidance(3)
        keys={r['rule_key'] for r in items}
        self.assertIn('validate_success',keys)
        self.assertLessEqual(len(items),5)
        self.assertNotIn('consider_containment',keys)
        self.assertNotIn('review_post_activity',keys)
        self.assertNotIn('repair_confirmed_changes',keys)

    def test_t4_actual_evidence_conditional_response_only(self):
        incident,assessment,items=self.setup_guidance(4)
        keys={r['rule_key'] for r in items}
        self.assertTrue({'consider_containment','review_post_activity'} <= keys)
        self.assertLessEqual(len(items),5)
        containment=next(r for r in items if r['rule_key']=='consider_containment')
        self.assertIn('If unauthorized activity is substantiated',containment['action_text'])
        self.assertIn('analyst approval',containment['action_text'])
        self.assertTrue(json.loads(containment['evidence_snapshot'])['alert_ids'])
        self.assertEqual(containment['assessment_id'],assessment['id'])

    def test_unrelated_success_no_escalation(self):
        incident=self.sequence(2)
        self.add('bob-success',minute=2,user='bob',groups=['authentication_success'])
        self.assess(incident)
        items=self.generate(incident)
        self.assertNotIn('validate_success',{r['rule_key'] for r in items})
        self.assertEqual({r['category'] for r in items},{'Investigation','Monitoring'})

    def test_inconclusive_safe_guidance(self):
        incident,_=self.add('success-only',groups=['authentication_success'])
        assessment=self.assess(incident)
        self.assertEqual(assessment['evidence_state'],'Inconclusive')
        items=self.generate(incident)
        self.assertIn('obtain_context',{r['rule_key'] for r in items})
        self.assertEqual({r['category'] for r in items},{'Investigation','Monitoring'})

    def test_unassessed_asset_safe_guidance_even_with_t4(self):
        incident=self.sequence(4)
        with self.db:
            self.db.execute('UPDATE assets SET is_protected=0')
        assessment=self.assess(incident)
        self.assertIsNone(assessment['risk_level'])
        self.assertEqual({r['category'] for r in self.generate(incident)},{'Investigation','Monitoring'})

    def test_fallback_generic_no_attack_specific_actions(self):
        incident,_=self.add('file-change',groups=['syscheck'])
        assessment=self.assess(incident)
        self.assertEqual(assessment['evidence_state'],'Inconclusive')
        items=self.generate(incident)
        self.assertIn('obtain_context',{r['rule_key'] for r in items})
        self.assertNotIn('repair_confirmed_changes',{r['rule_key'] for r in items})

    def test_high_risk_low_confidence_emphasizes_review_without_risk_change(self):
        incident=self.sequence(2)
        self.add('unknown',minute=2,groups=[])
        assessment=self.assess(incident)
        before=self.unchanged_snapshot()
        items=self.generate(incident)
        self.assertEqual(assessment['risk_level'],'high')
        self.assertEqual(assessment['confidence'],'low')
        self.assertNotIn('Contextual risk:',items[0]['rationale'])
        self.assertNotIn('confidence:',items[0]['rationale'])
        self.assertEqual(before,self.unchanged_snapshot())

    def test_firedtimes_severity_mitre_counts_do_not_select_actions(self):
        incident,assessment,items=self.setup_guidance(2)
        with self.db:
            for row in self.db.execute('SELECT id,raw_alert FROM alerts').fetchall():
                raw=json.loads(row['raw_alert']); raw['rule']['firedtimes']=999999
                self.db.execute('UPDATE alerts SET rule_level=15,wazuh_mitre_ids=?,raw_alert=? WHERE id=?',
                    ('["T1110","T1059.001"]',json.dumps(raw),row['id']))
        self.assess(incident)
        newer=self.generate(incident)
        self.assertEqual([(r['rule_key'],r['action_text']) for r in items],[(r['rule_key'],r['action_text']) for r in newer])

    def test_no_assessment_no_legacy_fallback(self):
        incident=self.sequence(1)
        with self.assertRaises(ValueError):
            generate_contextual_recommendations(incident)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM contextual_recommendations').fetchone()[0],0)

    def test_same_assessment_idempotent_and_read_only_refresh(self):
        incident,assessment,items=self.setup_guidance()
        self.assertEqual([r['id'] for r in items],generate_contextual_recommendations(incident))
        self.assertEqual(items,self.generate(incident))
        client=self.client()
        for _ in range(2):
            self.assertEqual(client.get(f'/incidents/{incident}').status_code,200)
        self.assertEqual(items,recommendation_history(self.db,incident))
        self.assertEqual(decision_history(self.db,incident),[])

    def test_new_assessment_preserves_old_guidance_and_legacy(self):
        incident,assessment,old=self.setup_guidance(2)
        before=self.unchanged_snapshot()
        new_assessment=self.assess(incident)
        before_generation=self.unchanged_snapshot()
        newer=self.generate(incident)
        self.assertNotEqual(new_assessment['id'],assessment['id'])
        historical=[r for r in recommendation_history(self.db,incident) if r['assessment_id']==assessment['id']]
        self.assertEqual(old,historical)
        self.assertEqual(before_generation,self.unchanged_snapshot())
        self.assertEqual(before['incident_recommendations'],self.unchanged_snapshot()['incident_recommendations'])

    def test_all_decisions_attribution_comments_and_append_only_history(self):
        incident,assessment,items=self.setup_guidance()
        uid=self.user()
        for choice in ('accept','reject','further_investigation_required'):
            record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,choice,'Human reason')
        history=decision_history(self.db,incident)
        self.assertEqual([d['decision'] for d in history],['further_investigation_required','reject','accept'])
        self.assertTrue(all(d['user_id']==uid and d['analyst_name_snapshot']=='test-analyst' and d['created_at'] for d in history))
        self.assertTrue(all(d['comments']=='Human reason' for d in history))

    def test_admin_can_decide_and_deleted_user_keeps_name_snapshot(self):
        incident,assessment,items=self.setup_guidance()
        uid=self.user('admin')
        record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,'accept')
        with self.db:
            self.db.execute('DELETE FROM users WHERE id=?',(uid,))
        decision=decision_history(self.db,incident)[0]
        self.assertIsNone(decision['user_id'])
        self.assertEqual(decision['analyst_name_snapshot'],'test-admin')

    def test_inactive_user_invalid_value_and_long_comment_rejected(self):
        incident,assessment,items=self.setup_guidance()
        uid=self.user(active=0)
        with self.assertRaises(PermissionError):
            record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,'accept')
        for choice,comment in [('', ''),('auto_accept',''),('accept','x'*4001)]:
            with self.assertRaises(ValueError):
                record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,choice,comment)
        self.assertEqual(decision_history(self.db,incident),[])

    def test_cross_incident_and_stale_assessment_decisions_rejected(self):
        incident,assessment,items=self.setup_guidance()
        uid=self.user()
        other,_=self.add('other',user='bob',source='192.0.2.2')
        other_assessment=self.assess(other)
        other_items=self.generate(other)
        with self.assertRaises(LookupError):
            record_analyst_decision(incident,assessment['id'],other_items[0]['id'],uid,'accept')
        self.assess(incident)
        with self.assertRaises(ValueError):
            record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,'accept')
        with self.assertRaises(sqlite3.IntegrityError),self.db:
            self.db.execute('''INSERT INTO analyst_decisions(incident_id,assessment_id,incident_recommendation_id,
                user_id,analyst_name_snapshot,decision) VALUES(?,?,?,?,?,'accept')''',
                (incident,assessment['id'],other_items[0]['id'],uid,'user'))

    def test_no_automatic_response_or_incident_status_changes(self):
        incident=self.sequence(4)
        assessment=self.assess(incident)
        uid=self.user()
        before=self.unchanged_snapshot()
        items=self.generate(incident)
        record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,'accept')
        self.assertEqual(before,self.unchanged_snapshot())
        self.assertEqual(self.db.execute('SELECT status FROM incidents WHERE id=?',(incident,)).fetchone()[0],'open')

    def test_ui_auth_csrf_explicit_choice_and_escaping(self):
        incident,assessment,items=self.setup_guidance()
        client=self.client()
        path=f'/incidents/{incident}/analyst-decisions'
        data={'assessment_id':str(assessment['id']),'recommendation_id':str(items[0]['id']),
              'decision':'accept','comments':'<script>alert(1)</script>','csrf_token':'test-token','user_id':'999999'}
        self.assertEqual(app.test_client().post(path,data=data).status_code,302)
        self.assertEqual(client.post(path,data={**data,'csrf_token':''}).status_code,400)
        self.assertEqual(client.post(path,data={**data,'decision':''}).status_code,400)
        self.assertEqual(client.get(path).status_code,405)
        response=client.post(path,data=data,follow_redirects=True)
        self.assertEqual(response.status_code,200)
        self.assertIn(b'&lt;script&gt;alert(1)&lt;/script&gt;',response.data)
        self.assertNotIn(b'<script>alert(1)</script>',response.data)
        self.assertIn(b'No response action was executed',response.data)
        self.assertIn(b'value="" selected disabled>Select a decision',response.data)
        self.assertNotIn(b'value="accept" selected',response.data)
        self.assertEqual(decision_history(self.db,incident)[0]['analyst_name_snapshot'],'analyst-test')

    def test_ui_assessment_workflow_generates_guidance(self):
        incident=self.sequence(3)
        client=self.client()
        response=client.post(f'/incidents/{incident}/investigations',data={'csrf_token':'test-token'},follow_redirects=True)
        self.assertEqual(response.status_code,200)
        self.assertIn(b'Recommended Follow-up',response.data)
        self.assertTrue(recommendation_history(self.db,incident))
        self.assertEqual(decision_history(self.db,incident),[])

    def test_generation_failure_atomic_then_retry(self):
        incident=self.sequence(3)
        self.assess(incident)
        before=self.unchanged_snapshot()
        with self.db:
            self.db.execute('''CREATE TRIGGER reject_guidance BEFORE INSERT ON contextual_recommendations
                WHEN NEW.priority=2 BEGIN SELECT RAISE(ABORT,'test failure'); END''')
        with self.assertRaises(sqlite3.IntegrityError):
            generate_contextual_recommendations(incident)
        self.assertEqual(recommendation_history(self.db,incident),[])
        self.assertEqual(before,self.unchanged_snapshot())
        with self.db:
            self.db.execute('DROP TRIGGER reject_guidance')
        self.assertTrue(self.generate(incident))

    def test_broken_evidence_never_unlocks_t4_actions(self):
        incident=self.sequence(4)
        self.assess(incident)
        with self.db:
            self.db.execute('DELETE FROM investigation_finding_alerts')
        items=self.generate(incident)
        self.assertEqual({r['category'] for r in items},{'Investigation','Monitoring'})
        self.assertIn('obtain_context',{r['rule_key'] for r in items})

    def test_old_decision_not_carried_to_new_recommendation_set(self):
        incident,assessment,items=self.setup_guidance()
        uid=self.user()
        record_analyst_decision(incident,assessment['id'],items[0]['id'],uid,'accept','Original decision')
        self.assess(incident)
        newer=self.generate(incident)
        history=decision_history(self.db,incident)
        self.assertEqual(len(history),1)
        self.assertFalse(any(d['incident_recommendation_id'] in {r['id'] for r in newer} for d in history))
        response=self.client().get(f'/incidents/{incident}')
        self.assertIn(b'No analyst decision recorded.',response.data)
        self.assertIn(b'Original decision',response.data)


if __name__=='__main__':
    unittest.main()
