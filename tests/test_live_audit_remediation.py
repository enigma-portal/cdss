"""Regressions for verified live defects; all synthetic records use temporary DBs."""
import copy
import json
import unittest

import test_archive_evidence as fixtures
from run import app
from app.services.archive_evidence import _selected
from app.services.contextual_risk import _load
from app.services.incident_processor import process_alert
from app.services.investigation import _archive_alerts, run_investigation
from app.services.playbook_registry import FILE_PROCESS, _values, select_playbook


class SelectorInputRegressionTests(unittest.TestCase):
    def test_collection_shapes_normalize_and_select_identically(self):
        selections=[]
        for factory in (list,tuple,set,frozenset):
            with self.subTest(shape=factory.__name__):
                events=factory(('11','1',1))
                self.assertEqual(_values(events),{'1','11'})
                selection=select_playbook({'mitre_ids':[]},{
                    'event_id':events,'rule_groups':['windows','sysmon','sysmon_process-anomalies'],
                    'process_name':['C:/Windows/System32/svchost.exe']})
                self.assertEqual(selection.playbook.key,FILE_PROCESS)
                selections.append((selection.playbook.key,selection.reason,selection.matched_triggers))
        self.assertTrue(all(item==selections[0] for item in selections))

    def test_security_process_alias_is_event_specific(self):
        for event_id in ('1','7036','4688'):
            source={'data':{'win':{'system':{'eventID':event_id},
                'eventdata':{'newProcessName':'C:/Windows/created.exe'}}}}
            fields=_selected(source)
            self.assertEqual(fields.get('process_name'),
                'C:/Windows/created.exe' if event_id=='4688' else None)
        source['data']['win']['eventdata']['image']='C:/Explicit/existing.exe'
        self.assertEqual(_selected(source)['process_name'],'C:/Explicit/existing.exe')


class LiveAuditEvidenceRegressionTests(unittest.TestCase):
    setUp=fixtures.ArchiveEvidenceTests.setUp
    tearDown=fixtures.ArchiveEvidenceTests.tearDown
    enabled_connector=fixtures.ArchiveEvidenceTests.enabled_connector
    retrieve=fixtures.ArchiveEvidenceTests.retrieve

    def trigger(self):
        event={'id':'trigger-shared-id','timestamp':'2026-10-09T07:00:00Z',
            'agent':{'id':'001','name':'LAB-001'},
            'rule':{'id':'61618','level':12,'description':'Reported process',
                'groups':['windows','sysmon','sysmon_process-anomalies']},
            'data':{'win':{'system':{'eventID':'1'},'eventdata':{
                'image':'C:/Windows/System32/svchost.exe','user':'SYSTEM',
                'processId':'1234','commandLine':'svchost.exe -k fixture'}}}}
        process_alert(event)
        alert_id=self.db.execute('SELECT id FROM alerts WHERE wazuh_alert_id=?',(event['id'],)).fetchone()[0]
        self.enabled_connector()
        return event,alert_id

    def hit(self,event,doc='archive-distinct',timestamp=None,event_id=None):
        source=copy.deepcopy(event)
        if timestamp:source['timestamp']=timestamp
        if event_id:source['data']['win']['system']['eventID']=event_id
        return {'_index':'wazuh-archives-4.x-2026.10.09','_id':doc,'_source':source}

    def run_with(self,alert_id,hits):
        retrieval,client,_=self.retrieve(alert_id,hits=hits)
        case=self.db.execute('SELECT incident_id FROM investigations WHERE id=?',(retrieval,)).fetchone()[0]
        execution=run_investigation(case)
        findings={r['finding_key']:dict(r) for r in self.db.execute(
            'SELECT * FROM investigation_findings WHERE investigation_id=?',(execution,))}
        snapshot=json.loads(findings['linked_alert_evidence']['finding_value'])
        return retrieval,case,execution,findings,snapshot,client

    def test_selected_and_executed_playbook_match_without_legacy_group_alias(self):
        _,aid=self.trigger()
        retrieval,_,execution,findings,_,_=self.run_with(aid,[])
        selected=self.db.execute('SELECT selected_playbook_key,selected_playbook_source_hash '
            'FROM investigation_archive_runs WHERE investigation_id=?',(retrieval,)).fetchone()
        actual=self.db.execute('SELECT playbook_key,playbook_import_hash FROM investigations '
            'WHERE id=?',(execution,)).fetchone()
        self.assertEqual(tuple(selected),tuple(actual))
        self.assertEqual(actual['playbook_key'],FILE_PROCESS)
        self.assertEqual(findings['file_process_events']['finding_status'],'observed')

    def test_same_source_id_different_timestamp_is_retained(self):
        event,aid=self.trigger()
        _,_,_,_,snapshot,_=self.run_with(aid,[self.hit(event,timestamp='2026-10-09T07:00:01Z')])
        self.assertEqual(len(snapshot),2)
        archive=next(item for item in snapshot if item['id']<0)
        self.assertEqual(archive['wazuh_alert_id'],event['id'])
        self.assertEqual(archive['event_timestamp'],'2026-10-09T07:00:01+00:00')

    def test_same_source_id_and_timestamp_different_event_type_is_retained(self):
        event,aid=self.trigger()
        _,_,_,_,snapshot,_=self.run_with(aid,[self.hit(event,event_id='7036')])
        self.assertEqual(len(snapshot),2)
        archive=next(item for item in snapshot if item['id']<0)
        self.assertEqual(archive['source_fields']['event_id'],'7036')

    def test_distinct_documents_sharing_trigger_id_and_metadata_remain_distinct(self):
        event,aid=self.trigger()
        hits=[self.hit(event,doc=doc,timestamp='2026-10-09T07:00:01Z') for doc in ('document-A','document-B')]
        _,_,_,_,snapshot,_=self.run_with(aid,hits)
        archives=[item for item in snapshot if item['id']<0]
        self.assertEqual(len(archives),2)
        self.assertEqual({item['source_provenance']['source_document_id'] for item in archives},
                         {'document-A','document-B'})
        self.assertEqual({item['wazuh_alert_id'] for item in archives},{event['id']})

    def test_true_duplicate_document_is_counted_once(self):
        event,aid=self.trigger()
        retrieval,case,_,_,_,_=self.run_with(aid,[self.hit(event,timestamp='2026-10-09T07:00:01Z')])
        row=self.db.execute('SELECT * FROM investigation_archive_evidence WHERE investigation_id=?',
                            (retrieval,)).fetchone()
        db=self.db
        class RepeatedTransportRows:
            def execute(self,sql,params=()):
                if 'SELECT * FROM investigation_archive_evidence' in sql:return [row,row]
                return db.execute(sql,params)
        alert=dict(self.db.execute('SELECT * FROM alerts WHERE id=?',(aid,)).fetchone())
        incident=dict(self.db.execute('SELECT * FROM incidents WHERE id=?',(case,)).fetchone())
        self.assertEqual(len(_archive_alerts(RepeatedTransportRows(),incident,[alert])),1)

    def test_equivalent_trigger_archive_copy_is_not_double_counted(self):
        event,aid=self.trigger()
        # Different source timezone text represents exactly the same UTC event.
        _,_,_,findings,snapshot,_=self.run_with(aid,[self.hit(event,timestamp='2026-10-09T08:00:00+01:00')])
        self.assertEqual([item['id'] for item in snapshot],[aid])
        self.assertEqual(len(json.loads(findings['file_process_events']['finding_value'])),1)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_archive_evidence').fetchone()[0],1)

    def test_same_id_time_type_with_different_evidence_is_not_a_copy(self):
        event,aid=self.trigger();hit=self.hit(event)
        hit['_source']['data']['win']['eventdata']['commandLine']='svchost.exe -k distinct-context'
        _,_,_,_,snapshot,_=self.run_with(aid,[hit])
        self.assertEqual(len(snapshot),2)

    def test_security_4688_process_flows_from_raw_to_snapshot_and_finding(self):
        event,aid=self.trigger()
        source={'id':'security-process','timestamp':'2026-10-09T07:00:01Z',
            'agent':{'id':'001'},'rule':{'id':'67027','level':3,'groups':['windows',' WEF']},
            'data':{'win':{'system':{'eventID':'4688'},'eventdata':{
                'newProcessName':'C:/Windows/System32/svchost.exe',
                'parentProcessName':'C:/Windows/System32/services.exe',
                'commandLine':'svchost.exe -k security-event'}}}}
        original=copy.deepcopy(source);hit=self.hit(event);hit['_source']=source
        retrieval,_,execution,findings,snapshot,client=self.run_with(aid,[hit])
        self.assertEqual(source,original)
        self.assertIn('data.win.eventdata.newProcessName',client.search_documents.call_args_list[0].args[0]['_source'])
        row=self.db.execute('SELECT * FROM investigation_archive_evidence WHERE investigation_id=?',(retrieval,)).fetchone()
        fields=json.loads(row['selected_fields_json'])
        self.assertEqual(fields['process_name'],source['data']['win']['eventdata']['newProcessName'])
        saved=next(item for item in snapshot if item['id']==-row['id'])
        self.assertEqual(saved['source_fields']['process_name'],fields['process_name'])
        self.assertEqual(saved['source_fields']['event_id'],'4688')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_finding_archive_evidence '
            'WHERE finding_id=? AND archive_evidence_id=?',
            (findings['linked_alert_evidence']['id'],row['id'])).fetchone()[0],1)
        # Metadata support does not turn a Security event into a Sysmon category.
        self.assertNotIn(-row['id'],{item['alert_id'] for item in json.loads(findings['file_process_events']['finding_value'])})

    def test_historical_security_snapshot_remains_valid_without_rewriting(self):
        event,_=self.trigger();security=copy.deepcopy(event)
        security['id']='historical-security';security['rule']['id']='67027'
        security['rule']['groups']=['windows',' WEF'];security['data']['win']={
            'system':{'eventID':'4688'},'eventdata':{'newProcessName':'C:/Security/process.exe'}}
        case=process_alert(security)['incident_id'];execution=run_investigation(case)
        row=self.db.execute("SELECT id,finding_value FROM investigation_findings WHERE investigation_id=? "
            "AND finding_key='linked_alert_evidence'",(execution,)).fetchone()
        value=json.loads(row['finding_value'])
        for item in value:item['source_fields'].pop('process_name',None)
        original=json.dumps(value)
        with self.db:self.db.execute('UPDATE investigation_findings SET finding_value=? WHERE id=?',(original,row['id']))
        investigation=self.db.execute('SELECT * FROM investigations WHERE id=?',(execution,)).fetchone()
        _load(self.db,investigation)
        self.assertEqual(self.db.execute('SELECT finding_value FROM investigation_findings WHERE id=?',
                                        (row['id'],)).fetchone()[0],original)
        self.assertEqual(json.loads(self.db.execute('SELECT raw_alert FROM alerts WHERE wazuh_alert_id=?',
                                                  (security['id'],)).fetchone()[0]),security)


if __name__=='__main__':unittest.main()
