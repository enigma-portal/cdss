"""OFFLINE integration fixtures, NOT live Wazuh detections or attack executions.

Only the HTTP transport is simulated. Connector setup, encryption, Indexer response
parsing, poller/cursor, ingestion, correlation and authenticated analyst forms run
normally against a disposable database. No production credentials/data are used.
"""
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import app.database as database
from app.database.seed import seed_knowledge_base
from app.services.poller import _poll_once, _bounded_integer
from app.services.dashboard_context import overview_data
from run import app
from app.mitre.taxii_sync import sync_enterprise_attack
from test_taxii_sync import stix_technique


class PhaseNineEndToEndTests(unittest.TestCase):
    def setUp(self):
        # Fail closed if any test accidentally escapes the simulated transport.
        self.network_guard=patch('socket.socket.connect',side_effect=AssertionError('Offline tests forbid network connections'))
        self.network_guard.start()
        self.addCleanup(self.network_guard.stop)
        self.directory=tempfile.TemporaryDirectory()
        self.original=database.DATABASE
        database.DATABASE=Path(self.directory.name)/'phase9-offline.db'
        self.key_patch=patch('app.services.secret_store.KEY_FILE',Path(self.directory.name)/'test-connector.key')
        self.key_patch.start()
        seed_knowledge_base()
        # Reference input (not incident results): names/tactics match the local
        # official catalogue imported in Phase 3. Exercise its normal synchronizer.
        catalogue=Mock()
        catalogue.fetch_enterprise_objects.return_value=[
            stix_technique('T1110','Brute Force',('credential-access',)),
            stix_technique('T1078','Valid Accounts',('stealth','persistence','privilege-escalation','initial-access')),
            stix_technique('T1078.002','Domain Accounts',('stealth','persistence','privilege-escalation','initial-access'))]
        sync_enterprise_attack(catalogue)
        self.db=database.get_db_connection()
        self.client=app.test_client()
        self.client.get('/setup')
        self.post('/setup',username='phase9-test-admin',password='OfflineFixture123!',confirmation='OfflineFixture123!')
        self.post('/logout')
        self.client.get('/login')
        self.post('/login',username='phase9-test-admin',password='OfflineFixture123!')
        self.assertEqual(self.client.get('/admin/assets').status_code,200)
        self.post('/admin/assets',asset_name='Phase9 offline fixture asset',asset_type='Server',
            asset_role='Authentication Server',os_family='Linux',os_name='Ubuntu Server',
            ip_address='192.0.2.20',wazuh_agent_id='phase9-agent',criticality='high',is_protected='1')
        self.asset=self.db.execute('SELECT * FROM assets').fetchone()
        self.assertIsNotNone(self.asset)
        self.assertEqual(self.asset['criticality'],'high')
        self.post('/admin/siem-connections',name='Phase9 OFFLINE fixture',connector_type='wazuh_indexer',
            base_url='https://192.0.2.10',port='9200',index_pattern='wazuh-alerts-*',
            username='fixture-reader',password='OfflineFixtureSecret123!',verify_tls='1')
        self.cid=self.db.execute('SELECT id FROM siem_connections').fetchone()[0]
        self.documents=[]
        self.queries=[]
        self.http_patch=patch('app.services.wazuh_indexer._open_no_redirect',side_effect=self.http)
        self.transport=self.http_patch.start()
        self.post(f'/admin/siem-connections/{self.cid}/test')
        self.assertEqual(self.db.execute('SELECT status FROM siem_connections').fetchone()[0],'connected')
        self.post(f'/admin/siem-connections/{self.cid}/toggle')

    def tearDown(self):
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])
        self.http_patch.stop()
        self.db.close()
        self.key_patch.stop()
        database.DATABASE=self.original
        self.directory.cleanup()

    def test_poll_validation_error_does_not_echo_source_secrets(self):
        event=self.event('unsafe-level',0,'authentication_failed')
        event['rule']['level']='password=DO-NOT-ECHO'
        with self.assertLogs('app.services.poller',level='WARNING') as logs:
            _poll_once(100,0)
        self.assertNotIn('DO-NOT-ECHO',' '.join(logs.output))
        self.assertNotIn('DO-NOT-ECHO',self.db.execute('SELECT last_error FROM siem_connections').fetchone()[0])

    def test_polling_correlation_boundaries_and_unmapped_assets(self):
        self.post('/admin/assets',asset_name='Second isolated asset',asset_type='Server',
            asset_role='Other',os_family='Linux',os_name='Ubuntu Server',
            wazuh_agent_id='second-agent',criticality='medium',is_protected='1')
        self.event('first',0,'authentication_failed')
        self.event('related',1,'authentication_failed')
        other=self.event('other-entity',2,'authentication_failed',user='different-account')
        other['data']['srcip']='192.0.2.99'
        other=self.event('other-asset',3,'authentication_failed')
        other['agent']['id']='second-agent'
        self.event('outside-window',20,'authentication_failed')
        for name in ('unmapped1','unmapped2'):
            self.event(name,21,'authentication_failed')['agent']['id']='unknown-agent'
        _poll_once(100,0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],7)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts WHERE asset_id IS NULL').fetchone()[0],2)
        from app.services.alert_view import list_alerts
        with app.app_context():
            groups, pagination=list_alerts(self.db,{})
        self.assertEqual(pagination['raw_total'],7)
        self.assertEqual(pagination['total'],4)
        self.assertTrue(any(group['occurrences']==2 for group in groups))
        # A subsequent poll still cannot create a case without an analyst click.
        self.event('after-closure',22,'authentication_failed')
        _poll_once(100,0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
        unmapped_alert=self.db.execute("SELECT id FROM alerts WHERE wazuh_alert_id='phase9-offline-unmapped1'").fetchone()[0]
        self.post(f'/alerts/groups/{unmapped_alert}/investigate')
        unmapped=self.db.execute("SELECT id FROM incidents WHERE case_origin='analyst_group'").fetchone()[0]
        assessment=self.db.execute('SELECT * FROM risk_assessments WHERE incident_id=?',(unmapped,)).fetchone()
        self.assertIsNone(assessment['risk_level'])
        self.assertIsNone(assessment['asset_criticality_snapshot'])

    def post(self,path,**data):
        with self.client.session_transaction() as session:
            token=session['csrf_token']
        response=self.client.post(path,data={'csrf_token':token,**data},follow_redirects=True)
        self.assertEqual(response.status_code,200)
        return response

    def http(self,request,context,timeout):
        # No socket is opened. This boundary models a realistic Indexer response.
        if request.full_url.endswith('/_cluster/health'):
            return io.BytesIO(json.dumps({'status':'green'}).encode())
        self.assertTrue(request.full_url.endswith('/wazuh-alerts-*/_search'))
        query=json.loads(request.data)
        self.queries.append(query)
        ascending=query['sort'][0]['timestamp']['order']=='asc'
        hits=sorted(self.documents,key=lambda hit:tuple(hit['sort']),reverse=not ascending)
        if query.get('search_after'):
            after=query['search_after']
            hits=[hit for hit in hits if tuple(hit['sort'])>(int(after[0]),after[1])]
        return io.BytesIO(json.dumps({'hits':{'hits':hits[:query['size']]}}).encode())

    def event(self,name,minute,group,mitre=None,user='phase9-user'):
        timestamp=datetime(2026,9,26,10,tzinfo=timezone.utc)+timedelta(minutes=minute)
        rule={'id':{'authentication_failed':'5716','authentication_success':'5715','syscheck':'550'}.get(group,'100001'),
              'description':'OFFLINE Phase9 fixture '+name,'level':5,'groups':[group], 'firedtimes':9999}
        if mitre:
            rule['mitre']={'id':mitre}
        raw={'id':'phase9-offline-'+name,'timestamp':timestamp.isoformat(),'rule':rule,
             'agent':{'id':'phase9-agent','name':'fixture-host','ip':'192.0.2.20'},
             'data':{'srcip':'192.0.2.30','srcuser':user}}
        if group=='syscheck':
            raw['syscheck']={'path':'/etc/ssh/sshd_config','event':'modified'}
        self.documents.append({'_id':'doc-'+name,'_source':raw,'sort':[int(timestamp.timestamp()*1000),'doc-'+name]})
        return raw

    def investigate_group(self):
        """Analyst click with isolated archive transport; no final outputs inserted."""
        capabilities={'indices':['wazuh-archives-4.x-2026.09.26'],'fields':{
            'timestamp':{'date':{'searchable':True,'aggregatable':True}},
            'agent.id':{'keyword':{'searchable':True,'aggregatable':True}}}}
        archive_hits=[{'_index':'wazuh-archives-4.x-2026.09.26',
                       '_id':'archive-'+hit['_id'],'_source':hit['_source']}
                      for hit in self.documents]
        archive_client=Mock()
        archive_client.field_capabilities.return_value=capabilities
        archive_client.search_documents.return_value={
            'hits':{'total':{'value':len(archive_hits),'relation':'eq'},'hits':archive_hits},
            '_shards':{'failed':0}}
        trigger=self.db.execute('SELECT id FROM alerts ORDER BY id LIMIT 1').fetchone()[0]
        with (patch('app.services.archive_evidence.create_connector',
                    return_value=Mock(client=archive_client)),
              patch('app.services.archive_evidence.unprotect_secret',return_value='offline-secret')):
            response=self.post(f'/alerts/groups/{trigger}/investigate')
        incident=self.db.execute("SELECT id FROM incidents WHERE case_origin='analyst_group'").fetchone()[0]
        return response,incident

    def verify(self,label,events,expected_state,expected_risk,criticality='high'):
        self.post(f"/admin/assets/{self.asset['id']}/edit",asset_name=self.asset['asset_name'],
            asset_type='Server',asset_role='Authentication Server',os_family='Linux',
            os_name='Ubuntu Server',ip_address='192.0.2.20',wazuh_agent_id='phase9-agent',
            criticality=criticality,is_protected='1')
        # Normal poller fetch -> HTTP decoder -> parser -> actual storage/processing.
        _poll_once(100,0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],len(events))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
        for event in events:
            row=self.db.execute('SELECT * FROM alerts WHERE wazuh_alert_id=?',(event['id'],)).fetchone()
            self.assertEqual(json.loads(row['raw_alert']),event)
            for key,expected in [('rule_id',event['rule']['id']),('rule_level',5),('agent_id','phase9-agent'),
                    ('source_ip','192.0.2.30'),('username',event['data']['srcuser']),('asset_id',self.asset['id']),('processing_status','processed')]:
                self.assertEqual(row[key],expected)
            self.assertEqual(json.loads(row['wazuh_mitre_ids']),event['rule'].get('mitre',{}).get('id',[]))
        count=len(events)
        self.assertEqual(self.db.execute("SELECT setting_value FROM system_settings WHERE setting_key='incident_correlation_window_minutes'").fetchone()[0],'15')
        mappings=self.db.execute('SELECT mapping_source FROM alert_mitre_techniques').fetchall()
        self.assertTrue(all(row[0]=='wazuh' for row in mappings))
        for row in self.db.execute('SELECT m.technique_name,m.catalogue_source FROM alert_mitre_techniques a JOIN mitre_techniques m ON m.technique_id=a.technique_id'):
            self.assertEqual(row['catalogue_source'],'taxii')
            self.assertIn(row['technique_name'],('Brute Force','Valid Accounts','Domain Accounts'))
        cursor=json.loads(self.db.execute('SELECT sort_values_json FROM ingestion_cursors').fetchone()[0])
        _poll_once(100,0)
        self.assertEqual(self.queries[-1]['search_after'],cursor)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],count)
        # Simulate an overlapping source page after restart: duplicates stay safe.
        repeated={'hits':{'hits':list(reversed(self.documents))}}
        with patch('app.services.wazuh_indexer._open_no_redirect',side_effect=lambda *a,**k:io.BytesIO(json.dumps(repeated).encode())):
            _poll_once(100,0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],count)
        legacy={table:[tuple(r) for r in self.db.execute('SELECT * FROM '+table+' ORDER BY id')]
                for table in ('risk_scores','incident_recommendations')}
        response,incident=self.investigate_group()
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],1)
        member_count=self.db.execute('''SELECT COUNT(*) FROM investigation_case_alerts
            WHERE case_id=?''',(incident,)).fetchone()[0]
        self.assertEqual(member_count,sum(e['rule']['groups']==['authentication_failed']
            for e in events) if any(e['rule']['groups']==['authentication_failed'] for e in events) else 1)
        assessment=self.db.execute("SELECT * FROM risk_assessments WHERE assessment_stage='contextual' ORDER BY id DESC").fetchone()
        self.assertEqual(assessment['evidence_state'],expected_state)
        self.assertEqual(assessment['risk_level'],expected_risk)
        self.assertEqual(assessment['asset_criticality_snapshot'],criticality)
        self.assertEqual(assessment['confidence'],'low' if expected_state=='Inconclusive' else 'high')
        self.assertTrue(assessment['rationale'])
        self.assertEqual(self.db.execute("SELECT playbook_key FROM investigations WHERE playbook_key<>'wazuh_archive_retrieval_v1'").fetchone()[0],
                         'generic_evidence_review_v1' if expected_state=='Inconclusive' else 'authentication_review_v1')
        recs=self.db.execute('SELECT * FROM contextual_recommendations ORDER BY priority').fetchall()
        self.assertTrue(recs)
        if expected_state in ('T1','T2','T3','Inconclusive'):
            self.assertFalse(any(r['category'] in ('Containment','Remediation') for r in recs))
        if expected_state=='T4':
            self.assertTrue(any(r['category']=='Containment' for r in recs))
        failures=self.db.execute("SELECT finding_value FROM investigation_findings WHERE finding_key='authentication_failures'").fetchone()
        if failures:
            self.assertEqual(json.loads(failures[0])['observed_alert_count'],sum('authentication_failed' in e['rule']['groups'] for e in events))
        for choice in ('accept','reject','further_investigation_required'):
            self.post(f'/incidents/{incident}/analyst-decisions',assessment_id=str(assessment['id']),
                recommendation_id=str(recs[0]['id']),decision=choice,comments='OFFLINE validation; no response executed')
        decisions=self.db.execute('SELECT * FROM analyst_decisions ORDER BY id').fetchall()
        self.assertEqual([r['decision'] for r in decisions],['accept','reject','further_investigation_required'])
        self.assertTrue(all(r['analyst_name_snapshot']=='phase9-test-admin' and r['created_at'] for r in decisions))
        self.assertEqual(self.db.execute('SELECT status FROM incidents').fetchone()[0],'open')
        dashboard=overview_data()
        self.assertEqual(dashboard['total'],1)
        self.assertEqual(dashboard['risks'][expected_risk or 'unassessed'],1)
        for text in (b'Key Findings',b'Recommended Follow-up',b'Decision History',expected_state.encode()):
            self.assertIn(text,response.data)
        self.assertEqual(self.client.get('/').status_code,200)
        self.assertEqual(self.client.get('/incidents').status_code,200)
        for table,before in legacy.items():
            self.assertEqual(before,[tuple(r) for r in self.db.execute('SELECT * FROM '+table+' ORDER BY id')])
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])
        print('OFFLINE ONLY',label,expected_state,expected_risk or 'Unassessed',
              'alerts',len(events),'incident',incident,'pipeline/forms passed; Wazuh detection NOT tested')

    def test_a_isolated_authentication_fixture(self):
        self.verify('A',[self.event('a',0,'authentication_failed',['T1110'])],'T1','low','low')

    def test_b_repeated_failures_fixture(self):
        self.verify('B',[self.event('b1',0,'authentication_failed',['T1110']),self.event('b2',1,'authentication_failed',['T1110'])],'T2','medium','medium')

    def test_c_related_success_fixture(self):
        self.verify('C',[self.event('c1',0,'authentication_failed',['T1110']),self.event('c2',1,'authentication_failed',['T1110']),
                         self.event('c3',2,'authentication_success',['T1078','T1078.002'])],'T3','high')

    def test_d_supported_later_activity_fixture(self):
        self.verify('D',[self.event('d1',0,'authentication_failed'),self.event('d2',1,'authentication_failed'),
                         self.event('d3',2,'authentication_success'),self.event('d4',3,'syscheck')],'T4','critical','critical')

    def test_missing_poll_settings_use_defaults(self):
        self.assertEqual(_bounded_integer(None,30,10,3600),30)

    def test_legacy_maintenance_requires_explicit_opt_in_before_database_access(self):
        from app.services import rescore_incidents, rebuild_guidance
        for module in (rescore_incidents,rebuild_guidance):
            with self.subTest(module=module.__name__), patch.object(module,'get_db_connection') as db, patch('sys.stderr',new_callable=io.StringIO):
                with self.assertRaises(SystemExit):
                    module.main([])
                db.assert_not_called()

    def test_malformed_source_does_not_advance_cursor(self):
        self.event('valid',0,'authentication_failed')
        _poll_once(100,0)
        cursor=tuple(self.db.execute('SELECT event_timestamp,document_id FROM ingestion_cursors').fetchone())
        self.documents.append({'_id':'broken','_source':None,'sort':[int(cursor[0])+1000,'broken']})
        _poll_once(100,0)
        self.assertEqual(tuple(self.db.execute('SELECT event_timestamp,document_id FROM ingestion_cursors').fetchone()),cursor)
        self.assertEqual(self.db.execute('SELECT status FROM siem_connections').fetchone()[0],'error')

    def test_null_optional_level_can_be_ingested_without_severity_filter(self):
        event=self.event('null-level',0,'authentication_failed')
        event['rule']['level']=None
        _poll_once(100,0)
        row=self.db.execute('SELECT rule_level,processing_status FROM alerts').fetchone()
        self.assertIsNotNone(row)
        self.assertIsNone(row['rule_level'])
        self.assertEqual(row['processing_status'],'processed')

    def test_fallback_fixture(self):
        self.verify('Fallback',[self.event('fallback',0,'windows')],'Inconclusive',None)

    def test_disabled_connector_does_not_fetch(self):
        self.post(f'/admin/siem-connections/{self.cid}/toggle')
        self.transport.reset_mock()
        _poll_once(100,0)
        self.transport.assert_not_called()

    def test_unexpected_connection_failure_does_not_expose_credentials(self):
        with patch('app.services.wazuh_indexer._open_no_redirect',side_effect=RuntimeError('password=SHOULD-NOT-LEAK')):
            response=self.post(f'/admin/siem-connections/{self.cid}/test')
        self.assertNotIn(b'SHOULD-NOT-LEAK',response.data)
        self.assertNotIn('SHOULD-NOT-LEAK',self.db.execute('SELECT last_error FROM siem_connections').fetchone()[0])
        self.assertFalse(any('SHOULD-NOT-LEAK' in (r[0] or '') for r in self.db.execute('SELECT details FROM connector_audit')))


if __name__=='__main__':
    unittest.main()
