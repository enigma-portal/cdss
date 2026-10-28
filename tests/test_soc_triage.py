"""Offline SOC triage and retention regressions; disposable storage only."""
import unittest
from datetime import datetime, timezone, timedelta

import test_alert_grouping as fixtures
from run import app
from app.services.triage import triage_page, triage_overview, family_children
from app.services.alert_retention import preview_retention, purge_retention
from app.services.incident_processor import ingest_source_alert
from app.services.archive_evidence import _ensure_case
from app.services.alert_view import group_context


class SocTriageTests(unittest.TestCase):
    setUp = fixtures.AlertGroupingTests.setUp
    tearDown = fixtures.AlertGroupingTests.tearDown
    client = fixtures.AlertGroupingTests.client

    def admin(self):
        with self.db:
            return self.db.execute("INSERT INTO users(username,password_hash,role) VALUES('retention-admin','unused','admin')").lastrowid

    def add(self, name, level=12, agent='001', path='a.dll', minute=0, **extra):
        source = dict(id=name,timestamp=f'2026-10-09T07:{minute:02d}:00Z',
            rule=dict(id=extra.pop('rule','900'),description='Repeated family',level=level),
            agent=dict(id=agent,name='WIN-'+agent),syscheck=dict(path=path),
            data=extra)
        return ingest_source_alert(source)['alert_id']

    def page(self, **args):
        with app.app_context():
            return triage_page(self.db,args)

    def case(self, alert_id):
        with app.app_context(), self.db:
            return _ensure_case(group_context(self.db,alert_id),self.db)

    def test_priority_queue_deterministic_and_landing_action(self):
        low=self.add('low',1,rule='low')
        high=self.add('high',9,rule='high')
        critical=self.add('critical',12,rule='critical')
        latest=self.add('latest',12,rule='latest',minute=2)
        items,_=self.page(view='needs')
        self.assertEqual([r['representative_id'] for r in items[:2]],[latest,critical])
        self.assertGreater([r['representative_id'] for r in items].index(low),
                           [r['representative_id'] for r in items].index(high))
        self.case(latest)
        self.assertEqual(self.page()[0][0]['representative_id'],critical)
        html=self.client().get('/').data.decode()
        self.assertIn('Investigate Next',html)
        self.assertIn(f'/alerts/groups/{critical}/investigate',html)
        self.assertIn('CRITICAL',html)
        self.assertIn('class="priority-reason"',html)

    def test_family_consolidates_artifacts_preserving_raw_and_assets(self):
        first=self.add('a',path='a.dll')
        self.add('b',path='b.dll',minute=1)
        self.add('c',path='a.dll',minute=2)
        self.add('other',agent='002')
        items,pagination=self.page()
        self.assertEqual(pagination['total'],2)
        family=next(item for item in items if item['agent_id']=='001')
        self.assertEqual((family['child_count'],family['occurrences']),(2,3))
        with app.app_context():
            children=family_children(self.db,family['representative_id'],{})
        self.assertEqual({r['syscheck_path'] for r in children['items']},{'a.dll','b.dll'})
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],4)
        client=self.client()
        self.assertEqual(client.get(f'/alerts/{first}').status_code,200)
        self.assertEqual(client.get(f'/alerts/families/{family["representative_id"]}').status_code,200)

    def test_context_boundaries_and_composed_filters(self):
        self.add('a',srcip='192.0.2.1',srcuser='alice')
        self.add('b',srcip='192.0.2.2',srcuser='alice')
        self.add('c',srcip='192.0.2.1',srcuser='bob')
        self.assertEqual(self.page()[1]['total'],3)
        args=dict(period='custom',priority='Critical',agent='001',status='Needs Investigation',
                  view='urgent',q='Repeated',**{'from':'2026-10-09T07:00','to':'2026-10-09T07:01'})
        self.assertEqual(self.page(**args)[1]['total'],3)
        self.assertEqual(self.page(**{**args,'priority':'Low'})[1]['total'],0)
        self.assertEqual(self.page(period='custom',**{'from':'bad','to':'bad'})[1]['total'],0)
        self.assertEqual(self.client().get('/alerts?view=needs&priority=Critical').status_code,200)

    def test_new_activity_links_prior_case_without_changing_membership(self):
        old=self.add('old')
        case=self.case(old)
        with self.db:
            self.db.execute("UPDATE incidents SET created_at='2026-10-09T07:00:00Z' WHERE id=?",(case,))
        before=[tuple(r) for r in self.db.execute('SELECT * FROM investigation_case_alerts')]
        new=self.add('new',minute=3,path='new.dll')
        items,_=self.page(view='new')
        self.assertEqual(items[0]['representative_id'],new)
        self.assertEqual(items[0]['prior_case']['id'],case)
        self.assertEqual(before,[tuple(r) for r in self.db.execute('SELECT * FROM investigation_case_alerts')])

    def test_retention_preview_deletion_protection_and_history(self):
        old=self.add('protected')
        case=self.case(old)
        unlinked=self.add('unlinked',minute=1)
        before=[tuple(r) for r in self.db.execute('SELECT * FROM incidents')]
        values={'from':'2026-10-09T07:00','to':'2026-10-09T07:02'}
        preview=preview_retention(self.db,values)
        self.assertEqual((preview['total'],preview['eligible'],preview['protected'],preview['remaining']),(2,1,1,1))
        admin=self.admin()
        from app.services.investigation import run_investigation
        from app.services.contextual_risk import assess_investigation
        from app.services.contextual_recommendations import generate_contextual_recommendations, record_analyst_decision
        execution=run_investigation(case)
        assessment=assess_investigation(case,execution)
        generate_contextual_recommendations(case)
        record_analyst_decision(case,assessment,None,admin,'further_investigation_required','Review retained evidence')
        before=[tuple(r) for r in self.db.execute('SELECT * FROM incidents')]
        tables=('incidents','investigation_case_alerts','investigations','investigation_findings',
                'risk_assessments','incident_recommendations','analyst_decisions')
        history={table:[tuple(r) for r in self.db.execute('SELECT * FROM '+table)] for table in tables}
        purge_retention(self.db,values,admin,preview['token'])
        self.assertIsNone(self.db.execute('SELECT id FROM alerts WHERE id=?',(unlinked,)).fetchone())
        self.assertIsNotNone(self.db.execute('SELECT id FROM alerts WHERE id=?',(old,)).fetchone())
        self.assertEqual(before,[tuple(r) for r in self.db.execute('SELECT * FROM incidents')])
        for table in tables:
            self.assertEqual(history[table],[tuple(r) for r in self.db.execute('SELECT * FROM '+table)],table)
        self.assertEqual(self.db.execute('SELECT deleted_count,protected_count FROM alert_retention_audit').fetchone()[:],(1,1))
        self.assertEqual(self.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_purge_rollback_and_stale_preview(self):
        alert=self.add('unlinked')
        values={'from':'2026-10-09T07:00','to':'2026-10-09T07:02'}
        preview=preview_retention(self.db,values)
        admin=self.admin()
        self.db.execute("CREATE TRIGGER fail_retention BEFORE INSERT ON alert_retention_audit BEGIN SELECT RAISE(ABORT,'test rollback'); END")
        self.db.commit()
        with self.assertRaises(Exception):
            purge_retention(self.db,values,admin,preview['token'])
        self.assertIsNotNone(self.db.execute('SELECT id FROM alerts WHERE id=?',(alert,)).fetchone())
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alert_retention_audit').fetchone()[0],0)
        self.add('later',minute=1)
        with self.assertRaisesRegex(ValueError,'changed since preview'):
            purge_retention(self.db,values,admin,preview['token'])

    def test_admin_only_and_csrf(self):
        client=self.client()
        with self.db:
            self.db.execute("UPDATE users SET role='admin'")
        self.assertEqual(client.get('/admin/alert-retention').status_code,200)
        self.assertEqual(client.post('/admin/alert-retention',data={'action':'purge'}).status_code,400)
        with self.db:
            self.db.execute("UPDATE users SET role='analyst'")
        self.assertEqual(client.get('/admin/alert-retention').status_code,403)
        self.assertEqual(client.post('/admin/alert-retention').status_code,403)

    def test_family_priority_filter_uses_highest_child_and_keeps_lower_artifacts(self):
        self.add('single',level=1,path='single.dll')
        for minute in (0,1,2):
            self.add('repeat-'+str(minute),level=1,path='repeated.dll',minute=minute)
        items,_=self.page(priority='Medium')
        self.assertEqual((items[0]['child_count'],items[0]['occurrences']),(2,4))
        self.assertEqual(self.page(priority='Low')[1]['total'],0)

    def test_pagination_and_all_filter_values_survive_next_link(self):
        for number in range(22):
            self.add('page-'+str(number),rule='r'+str(number),minute=number)
        args=dict(view='needs',priority='Critical',status='Needs Investigation',agent='001',q='Repeated',
                  period='custom',**{'from':'2026-10-09T07:00','to':'2026-10-09T07:59'})
        first,pagination=self.page(**args)
        second,_=self.page(**{**args,'page':'2'})
        self.assertEqual((len(first),len(second),pagination['total']),(20,2,22))
        self.assertFalse({r['representative_id'] for r in first}&{r['representative_id'] for r in second})
        from urllib.parse import urlencode
        html=self.client().get('/alerts?'+urlencode(args)).data.decode()
        self.assertIn('page=2',html)
        for key in ('priority=Critical','agent=001','period=custom','view=needs','q=Repeated'):
            self.assertIn(key,html)

    def test_archive_source_identity_and_future_fk_references_are_protected(self):
        old=self.add('case-trigger')
        case=self.case(old)
        from app.services.investigation import run_investigation
        execution=run_investigation(case)
        archived=self.add('archive-only',minute=1)
        future=self.add('future-reference',minute=2)
        with self.db:
            self.db.execute('''INSERT INTO investigation_archive_evidence
                (investigation_id,source_index,source_document_id,event_timestamp,agent_id,short_summary,selected_fields_json)
                VALUES(?,'offline-index','offline-document','2026-10-09T07:01:00Z','001','Offline evidence',
                '{"source_alert_id":"archive-only"}')''',(execution,))
            self.db.execute('CREATE TABLE future_audit(alert_ref INTEGER REFERENCES alerts(id) ON DELETE CASCADE)')
            self.db.execute('INSERT INTO future_audit VALUES(?)',(future,))
        preview=preview_retention(self.db,{'from':'2026-10-09T07:00','to':'2026-10-09T07:03'})
        self.assertEqual((preview['eligible'],preview['protected']),(0,3))

    def test_saved_unassigned_priority_remains_unassigned_in_queue_order(self):
        first=self.case(self.add('saved-unassigned',rule='a'))
        second=self.case(self.add('saved-low',rule='b'))
        with self.db:
            self.db.execute('UPDATE initial_alert_priorities SET initial_priority=NULL WHERE incident_id=?',(first,))
            self.db.execute("UPDATE initial_alert_priorities SET initial_priority='Low' WHERE incident_id=?",(second,))
        items,_=self.page(view='investigated')
        self.assertEqual([r['case_id'] for r in items],[second,first])
        self.assertIsNone(items[-1]['initial_priority'].level)

    def test_family_expansion_names_sysmon_artifacts(self):
        for name in ('a.dll','b.dll'):
            self.add(name,path=None,win={'eventdata':{'targetFilename':'C:/Temp/'+name}})
        items,_=self.page()
        self.assertEqual(items[0]['child_count'],2)
        html=self.client().get('/alerts/families/'+str(items[0]['representative_id'])).data.decode()
        for name in ('a.dll','b.dll'):
            self.assertIn('Artifact: C:/Temp/'+name,html)

    def test_admin_retention_requires_preview_then_explicit_confirmation(self):
        alert=self.add('confirmed-delete')
        admin=self.admin()
        client=self.client()
        with client.session_transaction() as session:
            session['user_id']=admin
            session['csrf_token']='soc-retention-test-token'
        values={'from':'2026-10-09T07:00','to':'2026-10-09T07:01',
                'csrf_token':'soc-retention-test-token'}
        client.post('/admin/alert-retention',data={**values,'action':'purge','confirm':'yes','preview_token':'fake'})
        self.assertIsNotNone(self.db.execute('SELECT id FROM alerts WHERE id=?',(alert,)).fetchone())
        response=client.post('/admin/alert-retention',data={**values,'action':'preview'})
        self.assertIn(b'Deletion preview',response.data)
        with client.session_transaction() as session:
            token=session['retention_preview_token']
        response=client.post('/admin/alert-retention',data={**values,'action':'purge','preview_token':token})
        self.assertIn(b'Explicit confirmation is required',response.data)
        self.assertIsNotNone(self.db.execute('SELECT id FROM alerts WHERE id=?',(alert,)).fetchone())
        response=client.post('/admin/alert-retention',data={**values,'action':'purge','preview_token':token,'confirm':'yes'})
        self.assertEqual(response.status_code,302)
        self.assertIsNone(self.db.execute('SELECT id FROM alerts WHERE id=?',(alert,)).fetchone())
        with client.session_transaction() as session:
            self.assertNotIn('retention_preview_token',session)

    def test_new_activity_matches_sqlite_owned_case_creation_timestamp(self):
        old=self.add('prior-case')
        case=self.case(old)
        created=self.db.execute('SELECT created_at FROM incidents WHERE id=?',(case,)).fetchone()[0]
        self.assertIsNone(datetime.fromisoformat(created).tzinfo)
        new=self.add('new-after-sqlite-case',minute=1,path='different.dll')
        after=datetime.fromisoformat(created).replace(tzinfo=timezone.utc)+timedelta(minutes=1)
        with self.db:
            self.db.execute('UPDATE alerts SET event_timestamp=? WHERE id=?',(after.isoformat(),new))
        items,_=self.page(view='new')
        self.assertEqual(len(items),1)
        self.assertEqual(items[0]['prior_case']['id'],case)
        self.assertEqual(items[0]['representative_id'],new)
        self.assertIsNone(items[0]['case_id'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_case_alerts WHERE case_id=?',(case,)).fetchone()[0],1)

    def test_family_link_survives_new_representative(self):
        first=self.add('first-family-link')
        original,_=self.page()
        self.assertEqual(original[0]['representative_id'],first)
        latest=self.add('later-family-member',minute=1)
        with app.app_context():
            family=family_children(self.db,first,{})
        self.assertIsNotNone(family)
        self.assertEqual(family['items'][0]['representative_id'],latest)
        self.assertEqual(family['items'][0]['occurrences'],2)
        response=self.client().get('/alerts/families/'+str(first))
        self.assertEqual(response.status_code,302)
        self.assertTrue(response.location.endswith(f'/alerts/groups/{latest}'))
