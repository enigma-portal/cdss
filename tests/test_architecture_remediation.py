"""Offline regression tests for the analyst-triggered grouped case path."""

import unittest

import test_alert_grouping as fixtures
from run import app
from app.services.alert_view import group_context
from app.services.archive_evidence import start_group_archive_retrieval
from app.services.contextual_risk import assess_investigation
from app.services.contextual_recommendations import generate_contextual_recommendations
from app.services.incident_processor import ingest_source_alert
from app.services.investigation import run_investigation
from app.services.initial_priority import calculate_initial_priority
from app.services.imported_playbooks import (
    load_imported_playbooks, verify_canonical_artifact,
)
from app.services.playbook_registry import imported_definition


class ArchitectureRemediationTests(unittest.TestCase):
    setUp = fixtures.AlertGroupingTests.setUp
    tearDown = fixtures.AlertGroupingTests.tearDown
    add_alert = fixtures.AlertGroupingTests.add_alert
    client = fixtures.AlertGroupingTests.client

    def test_production_ingestion_stores_without_opening_case(self):
        source = {'id':'new-source-alert','timestamp':'2026-10-09T07:00:00Z',
                  'rule':{'id':'5710','description':'Failed login','level':7,
                          'groups':['authentication_failed']},
                  'agent':{'id':'001','name':'WIN-001'},
                  'data':{'srcip':'192.0.2.10','srcuser':'alice'}}
        first = ingest_source_alert(source)
        second = ingest_source_alert(source)
        self.assertTrue(first['created'])
        self.assertFalse(second['created'])
        self.assertEqual(first['alert_id'],second['alert_id'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0],0)
        self.assertEqual(self.db.execute('SELECT processing_status FROM alerts').fetchone()[0],
                         'processed')

    def test_explicit_runtime_startup_and_wsgi_entry_point(self):
        from importlib import import_module
        from sys import modules
        from unittest.mock import patch
        import run
        with (patch('run.initialize_database') as initialize,
              patch('run.seed_knowledge_base') as seed,
              patch('run.backfill_recommendations') as backfill,
              patch('run.start_realtime_poller') as poller):
            run.prepare_runtime()
        initialize.assert_called_once_with()
        seed.assert_called_once_with()
        backfill.assert_called_once()
        poller.assert_called_once_with(run.app.config['SIEM_REALTIME_ENABLED'])
        modules.pop('wsgi',None)
        with patch('run.prepare_runtime') as prepare:
            self.assertIs(import_module('wsgi').app,run.app)
        prepare.assert_called_once_with()

    def test_priority_uses_bounded_project_rule_not_final_risk(self):
        base={'rule_level':4,'criticality':'low','occurrences':1,
              'wazuh_mitre_ids':[],'group_window_minutes':60}
        low=calculate_initial_priority(base,self.db)
        critical=calculate_initial_priority({**base,'criticality':'critical'},self.db)
        repeated=calculate_initial_priority({**base,'criticality':'critical',
            'occurrences':9000,'wazuh_mitre_ids':['T1110']},self.db)
        self.assertEqual(low.level,'Low')
        self.assertEqual(critical.level,'Medium')
        self.assertEqual(repeated.level,'High')
        self.assertEqual(repeated.occurrence_count_used,5)
        self.assertNotEqual(repeated.level,'Critical')
        self.assertEqual(calculate_initial_priority({**base,'criticality':None},self.db).level,None)

    def test_imported_playbooks_are_loaded_and_vendor_actions_unsupported(self):
        manifest=load_imported_playbooks()
        self.assertEqual(len(manifest),3)
        for key,artifact in manifest.items():
            definition=imported_definition(key)
            self.assertEqual(definition.source_title,artifact['source_title'])
            self.assertEqual({item.key for item in definition.evidence_requests},
                             set(artifact['check_keys']))
            self.assertTrue(any(not step['supported'] for step in artifact['steps']))
            self.assertFalse(verify_canonical_artifact(key,b'altered source'))

    def test_group_case_all_members_and_priority_snapshot_are_idempotent(self):
        first,_ = self.add_alert('first-new-group',0)
        second,_ = self.add_alert('second-new-group',1)
        from app.services.archive_evidence import _ensure_case
        with app.app_context():
            group = group_context(self.db,second)
            case_id = _ensure_case(group,self.db)
            repeated = _ensure_case(group,self.db)
        self.assertEqual(case_id,repeated)
        self.assertEqual([row[0] for row in self.db.execute('''SELECT alert_id FROM
            investigation_case_alerts WHERE case_id=? ORDER BY ordinal''',(case_id,))],
            [first,second])
        priority = self.db.execute('''SELECT * FROM initial_alert_priorities
            WHERE incident_id=?''',(case_id,)).fetchone()
        self.assertEqual(priority['initial_priority_model_version'],'cdss-initial-priority-v2')
        self.assertIn(priority['initial_priority'],('Low','Medium','High','Critical'))
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_archive_source_observations_feed_authentication_state(self):
        first,_ = self.add_alert('auth-a',0)
        second,_ = self.add_alert('auth-b',1)
        # A completed archive query with an actual later success record supports
        # the sequence; retrieval availability alone cannot do so.
        from unittest.mock import Mock,patch
        capabilities={'indices':['wazuh-archives-4.x-2026.10.09'],'fields':{
            'timestamp':{'date':{'searchable':True,'aggregatable':True}},
            'agent.id':{'keyword':{'searchable':True,'aggregatable':True}}}}
        hit={'_index':'wazuh-archives-4.x-2026.10.09','_id':'auth-success',
             '_source':{'id':'source-auth-success','timestamp':'2026-10-09T07:02:00Z',
                        'agent':{'id':'001'},
                        'rule':{'id':'5715','description':'Authentication succeeded',
                                'level':5,'groups':['authentication_success']},
                        'data':{'srcip':'192.0.2.10','srcuser':'alice'}}}
        client=Mock()
        client.field_capabilities.return_value=capabilities
        client.search_documents.return_value={'hits':{'total':{'value':1,'relation':'eq'},
                                                      'hits':[hit]},'_shards':{'failed':0}}
        with self.db:
            self.db.execute('''INSERT INTO siem_connections
                (name,connector_type,base_url,port,index_pattern,username,
                 encrypted_password,verify_tls,is_enabled,status)
                VALUES('offline','wazuh_indexer','https://fixture.invalid',9200,
                       'wazuh-alerts-*','reader',X'01',1,1,'connected')''')
        with (patch('app.services.archive_evidence.create_connector',
                    return_value=Mock(client=client)),
              patch('app.services.archive_evidence.unprotect_secret',return_value='secret')):
            with app.app_context():
                start_group_archive_retrieval(second)
        case=self.db.execute("SELECT id FROM incidents WHERE case_origin='analyst_group'").fetchone()[0]
        execution=run_investigation(case)
        assessment=assess_investigation(case,execution)
        result=self.db.execute('SELECT evidence_state FROM risk_assessments WHERE id=?',
                               (assessment,)).fetchone()[0]
        self.assertEqual(result,'T3')
        refs=self.db.execute('''SELECT COUNT(*) FROM investigation_finding_archive_evidence''').fetchone()[0]
        self.assertGreater(refs,0)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_file_process_group_uses_imported_playbook_and_archive_evidence(self):
        from unittest.mock import Mock,patch
        ingest_source_alert({'id':'file-source','timestamp':'2026-10-09T07:00:00Z',
            'rule':{'id':'92213','description':'File creation observed','level':8,
                    'groups':['sysmon','sysmon_eid11_detections']},
            'agent':{'id':'001','name':'WIN-001'},
            'data':{'srcip':'192.0.2.10','srcuser':'alice','win':{'system':{'eventID':'11'},
                    'eventdata':{'targetFilename':r'C:\Temp\sample.bin',
                                 'image':r'C:\Tools\cmd.exe'}}}})
        alert_id=self.db.execute("SELECT id FROM alerts WHERE wazuh_alert_id='file-source'").fetchone()[0]
        hit={'_index':'wazuh-archives-4.x-2026.10.09','_id':'file-process',
             '_source':{'id':'file-process','timestamp':'2026-10-09T07:01:00Z',
                'agent':{'id':'001'},
                'rule':{'id':'92001','description':'Process creation observed','level':8,
                        'groups':['sysmon','sysmon_eid1_detections']},
                'data':{'srcip':'192.0.2.10','srcuser':'alice',
                        'win':{'system':{'eventID':'1'},'eventdata':{
                            'image':r'C:\Tools\cmd.exe','commandLine':'cmd.exe /c whoami'}}}}}
        client=Mock()
        client.field_capabilities.return_value={'indices':['wazuh-archives-4.x-2026.10.09'],
            'fields':{'timestamp':{'date':{'searchable':True,'aggregatable':True}},
                      'agent.id':{'keyword':{'searchable':True,'aggregatable':True}}}}
        client.search_documents.return_value={'hits':{'total':{'value':1,'relation':'eq'},
            'hits':[hit]},'_shards':{'failed':0}}
        with self.db:
            self.db.execute('''INSERT INTO siem_connections
                (name,connector_type,base_url,port,index_pattern,username,
                 encrypted_password,verify_tls,is_enabled,status)
                VALUES('offline','wazuh_indexer','https://fixture.invalid',9200,
                       'wazuh-alerts-*','reader',X'01',1,1,'connected')''')
        with (patch('app.services.archive_evidence.create_connector',
                    return_value=Mock(client=client)),
              patch('app.services.archive_evidence.unprotect_secret',return_value='secret')):
            with app.app_context():
                start_group_archive_retrieval(alert_id)
        case=self.db.execute("SELECT id FROM incidents WHERE case_origin='analyst_group'").fetchone()[0]
        execution=run_investigation(case)
        self.assertEqual(self.db.execute('SELECT playbook_key FROM investigations WHERE id=?',
                                        (execution,)).fetchone()[0],'file_process_review_v1')
        self.assertTrue(self.db.execute('SELECT playbook_import_hash FROM investigations WHERE id=?',
                                        (execution,)).fetchone()[0])
        assessment=assess_investigation(case,execution)
        self.assertEqual(self.db.execute('SELECT evidence_state FROM risk_assessments WHERE id=?',
                                        (assessment,)).fetchone()[0],'T3')
        self.assertGreater(self.db.execute('SELECT COUNT(*) FROM investigation_finding_archive_evidence'
                                           ).fetchone()[0],0)
        self.assertTrue(generate_contextual_recommendations(case))
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_high_initial_priority_can_become_low_final_risk(self):
        with self.db:
            self.db.execute("UPDATE assets SET criticality='low' WHERE wazuh_agent_id='001'")
        ingest_source_alert({'id':'isolated-high-level','timestamp':'2026-10-09T07:00:00Z',
            'rule':{'id':'5710','description':'Failed authentication observed','level':12,
                    'groups':['authentication_failed']},
            'agent':{'id':'001','name':'WIN-001'},
            'data':{'srcip':'192.0.2.10','srcuser':'alice'}})
        alert_id=self.db.execute("SELECT id FROM alerts WHERE wazuh_alert_id='isolated-high-level'").fetchone()[0]
        from app.services.archive_evidence import _ensure_case
        with app.app_context():
            case=_ensure_case(group_context(self.db,alert_id),self.db)
        priority=self.db.execute('SELECT initial_priority FROM initial_alert_priorities WHERE incident_id=?',
                                 (case,)).fetchone()[0]
        execution=run_investigation(case)
        assessment=assess_investigation(case,execution)
        result=self.db.execute('SELECT evidence_state,risk_level FROM risk_assessments WHERE id=?',
                               (assessment,)).fetchone()
        self.assertEqual(priority,'High')
        self.assertEqual((result['evidence_state'],result['risk_level']),('T1','low'))

    def test_explicit_group_case_rerun_refreshes_archive_first(self):
        from unittest.mock import patch
        ingest_source_alert({'id':'rerun-source','timestamp':'2026-10-09T07:00:00Z',
            'rule':{'id':'5710','description':'Failed login','level':7,
                    'groups':['authentication_failed']},
            'agent':{'id':'001','name':'WIN-001'},
            'data':{'srcip':'192.0.2.10','srcuser':'alice'}})
        alert_id=self.db.execute("SELECT id FROM alerts WHERE wazuh_alert_id='rerun-source'").fetchone()[0]
        from app.services.archive_evidence import _ensure_case
        with app.app_context():
            case=_ensure_case(group_context(self.db,alert_id),self.db)
        client=self.client()
        with patch('app.routes.dashboard.start_group_archive_retrieval') as refresh:
            response=client.post(f'/incidents/{case}/investigations',
                                 data={'csrf_token':'test-token'})
        self.assertEqual(response.status_code,302)
        refresh.assert_called_once_with(alert_id)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM risk_assessments WHERE incident_id=? AND assessment_stage='contextual'",
                                         (case,)).fetchone()[0],1)

    def test_cross_agent_pivot_needs_actual_related_log_and_stays_advisory(self):
        from unittest.mock import Mock,patch
        for suffix,minute in (('one',0),('two',1)):
            ingest_source_alert({'id':'remote-'+suffix,
                'timestamp':f'2026-10-09T07:0{minute}:00Z',
                'rule':{'id':'60122','description':'Remote authentication failure',
                        'level':7,'groups':['authentication_failed','windows_security'],
                        'mitre':{'id':['T1021.001']}},
                'agent':{'id':'001','name':'WIN-001'},
                'data':{'srcip':'192.0.2.10','srcuser':'alice',
                        'win':{'system':{'eventID':'4625'}}}})
        first=self.db.execute("SELECT id FROM alerts WHERE wazuh_alert_id='remote-one'").fetchone()[0]
        second=self.db.execute("SELECT id FROM alerts WHERE wazuh_alert_id='remote-two'").fetchone()[0]
        caps={'indices':['wazuh-archives-4.x-2026.10.09'],'fields':{
            field:{kind:{'searchable':True,'aggregatable':True}}
            for field,kind in (('timestamp','date'),('agent.id','keyword'),
                ('data.srcip','ip'),('data.srcuser','keyword'))}}
        def archived(document_id,minute,agent):
            return {'_index':'wazuh-archives-4.x-2026.10.09','_id':document_id,
                '_source':{'id':document_id,'timestamp':f'2026-10-09T07:0{minute}:00Z',
                    'agent':{'id':agent},
                    'rule':{'id':'60123','description':'Remote authentication success',
                            'level':5,'groups':['authentication_success','windows_security']},
                    'data':{'srcip':'192.0.2.10','srcuser':'alice',
                            'win':{'system':{'eventID':'4624'}}}}}
        same=archived('same-success',2,'001')
        other=archived('other-success',3,'002')
        client=Mock()
        client.field_capabilities.return_value=caps
        client.search_documents.side_effect=[
            {'hits':{'total':{'value':1,'relation':'eq'},'hits':[same]},'_shards':{'failed':0}},
            {'hits':{'total':{'value':1,'relation':'eq'},'hits':[other]},'_shards':{'failed':0}}]
        with self.db:
            self.db.execute('''INSERT INTO siem_connections
                (name,connector_type,base_url,port,index_pattern,username,
                 encrypted_password,verify_tls,is_enabled,status)
                VALUES('offline','wazuh_indexer','https://fixture.invalid',9200,
                       'wazuh-alerts-*','reader',X'01',1,1,'connected')''')
        with (patch('app.services.archive_evidence.create_connector',
                    return_value=Mock(client=client)),
              patch('app.services.archive_evidence.unprotect_secret',return_value='secret')):
            with app.app_context():
                start_group_archive_retrieval(second)
        case=self.db.execute("SELECT id FROM incidents WHERE case_origin='analyst_group'").fetchone()[0]
        members=[row[0] for row in self.db.execute('''SELECT alert_id FROM
            investigation_case_alerts WHERE case_id=? ORDER BY ordinal''',(case,))]
        self.assertEqual(members,[first,second])
        self.assertEqual(self.db.execute('''SELECT cross_retrieval_status,cross_retrieved_count
            FROM investigation_archive_runs''').fetchone()[:],('available',1))
        execution=run_investigation(case)
        assessment=assess_investigation(case,execution)
        row=self.db.execute('SELECT evidence_state,risk_level FROM risk_assessments WHERE id=?',
                            (assessment,)).fetchone()
        self.assertEqual(row['evidence_state'],'T4')
        self.assertEqual(row['risk_level'],'critical')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM analyst_decisions').fetchone()[0],0)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])


if __name__ == '__main__':
    unittest.main()
