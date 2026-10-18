"""Verified product-audit regressions. All fixtures use disposable databases."""
import json
import unittest
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock

import test_alert_grouping as fixtures
from run import app
from app.services.alert_parser import parse_alert, stored_reported_destination_ip
from app.services.alert_view import alert_queue_snapshot, group_context
from app.services.asset_resolver import observed_agent_context
from app.services.dashboard_context import overview_data, incident_presentation, recommendation_presentation
from app.services.archive_evidence import _query_cross_asset, _cross_address, ArchiveUnavailable
from app.services.incident_processor import process_alert
from app.services.investigation import run_investigation


class ProductAuditTests(unittest.TestCase):
    setUp = fixtures.AlertGroupingTests.setUp
    tearDown = fixtures.AlertGroupingTests.tearDown
    add_alert = fixtures.AlertGroupingTests.add_alert
    client = fixtures.AlertGroupingTests.client

    def test_overview_queue_counts_and_real_receipt_times(self):
        for minute in (0,1,2):
            self.add_alert('overview-'+str(minute),minute)
        self.add_alert('unmapped-overview',3,agent='099')
        with app.app_context():
            queue=alert_queue_snapshot(self.db)
            overview=overview_data()
        self.assertEqual((queue['raw_total'],queue['total']),(4,2))
        self.assertEqual(len(queue['recent']),2)
        self.assertEqual(overview['alert_activity']['received_recently'],4)
        self.assertEqual(overview['asset_visibility'],dict(observed=2,mapped=1,unmapped=1,outside_scope=0))
        with self.db:
            self.db.execute("UPDATE alerts SET created_at='2000-01-01 00:00:00'")
        self.assertEqual(overview_data()['alert_activity']['received_recently'],0)
        page=self.client().get('/').get_data(as_text=True)
        self.assertIn('Wazuh alert activity',page)
        self.assertIn('Recent grouped detections',page)
        self.assertIn('Investigation activity',page)

    def test_empty_overview_does_not_invent_activity(self):
        overview=overview_data()
        self.assertEqual(overview['alert_activity']['raw_total'],0)
        self.assertEqual(overview['alert_activity']['total'],0)
        self.assertEqual(overview['alert_activity']['recent'],[])
        self.assertEqual(overview['asset_visibility']['observed'],0)

    def test_observed_agent_uses_latest_event_without_mapping_or_ip_inference(self):
        self.add_alert('agent-new',1,agent='099')
        self.add_alert('agent-old',0,agent='099')
        with self.db:
            self.db.execute("UPDATE alerts SET agent_name='Current',agent_ip='192.0.2.2' WHERE wazuh_alert_id='agent-new'")
            self.db.execute("UPDATE alerts SET agent_name='ZebraOld',agent_ip='192.0.2.200' WHERE wazuh_alert_id='agent-old'")
        before=self.db.execute('SELECT COUNT(*) FROM assets').fetchone()[0]
        row=observed_agent_context(self.db)[0]
        self.assertEqual((row['agent_name'],row['agent_ip'],row['asset_id']),('Current','192.0.2.2',None))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM assets').fetchone()[0],before)

    def sysmon(self,identifier='sysmon-network',destination='198.51.100.9'):
        return {'id':identifier,'timestamp':'2026-10-09T07:00:00Z','agent':{'id':'001','ip':'10.0.0.99'},
            'rule':{'id':'61603','level':7,'groups':['sysmon','sysmon_event3'], 'description':'Network connection'},
            'data':{'win':{'system':{'eventID':'3'},'eventdata':{'sourceIp':'192.0.2.44',
                'destinationIp':destination,'user':'LAB/alice','image':'C:/app.exe'}}}}

    def test_sysmon_network_ips_are_event_context_and_historical_rows_recover_read_only(self):
        event=self.sysmon()
        parsed=parse_alert(event)
        self.assertEqual((parsed.source_ip,parsed.destination_ip,parsed.agent_ip),('192.0.2.44','198.51.100.9','10.0.0.99'))
        case=process_alert(event)['incident_id']
        alert=self.db.execute('SELECT * FROM alerts WHERE wazuh_alert_id=?',(event['id'],)).fetchone()
        with self.db:
            self.db.execute('UPDATE alerts SET source_ip=NULL,destination_ip=NULL WHERE id=?',(alert['id'],))
        with app.app_context():
            group=group_context(self.db,alert['id'])
        self.assertEqual(group['members'][0]['destination_ip'],'198.51.100.9')
        execution=run_investigation(case)
        value=json.loads(self.db.execute("SELECT finding_value FROM investigation_findings WHERE investigation_id=? AND finding_key='linked_alert_evidence'",(execution,)).fetchone()[0])
        self.assertEqual((value[0]['source_ip'],value[0]['destination_ip']),('192.0.2.44','198.51.100.9'))
        stored=self.db.execute('SELECT source_ip,destination_ip,raw_alert FROM alerts WHERE id=?',(alert['id'],)).fetchone()
        self.assertEqual((stored[0],stored[1]),(None,None))
        self.assertEqual(json.loads(stored[2]),event)

    def test_destination_difference_remains_separate_group_for_historical_sysmon(self):
        for identifier,dest in [('network-one','198.51.100.1'),('network-two','198.51.100.2')]:
            process_alert(self.sysmon(identifier,dest))
        with self.db:
            self.db.execute('UPDATE alerts SET source_ip=NULL,destination_ip=NULL')
        with app.app_context():
            queue=alert_queue_snapshot(self.db)
        self.assertEqual(queue['total'],2)
        self.assertIsNone(stored_reported_destination_ip(json.dumps({'rule':{'groups':['other']},'data':{'win':{'system':{'eventID':3},'eventdata':{'destinationIp':'198.51.100.1'}}}})))

    def test_findings_presentation_uses_evaluated_archives_and_partial_coverage(self):
        saved={'id':3,'playbook_key':'file_process_review_v1','findings':[
            {'finding_key':'linked_alert_evidence','finding_status':'observed','finding_value':json.dumps([
                {'id':-1,'source_ip':'192.0.2.10','destination_ip':'198.51.100.8','username':'archive-user'}])},
            {'finding_key':'archive_coverage','finding_status':'unavailable','finding_value':json.dumps({'truncated':1})},
            {'finding_key':'cross_system_coverage','finding_status':'unavailable','finding_value':json.dumps({'cross_truncated':1})}]}
        timeline=[{'id':1,'rule_description':'Current alert','source_ip':'192.0.2.99','username':'new-user'}]
        view=incident_presentation({'title':'File'},None,timeline,[saved],None,[])
        text=' '.join(item['label'] for item in view['evidence'])
        self.assertIn('Network Source IP: 192.0.2.10',text)
        self.assertIn('Network Destination IP: 198.51.100.8',text)
        self.assertIn('Reported account: archive-user',text)
        self.assertNotIn('192.0.2.99',text)
        self.assertIn('Same-asset archive coverage is partial',text)
        self.assertIn('Other-system archive coverage is partial',text)

    def test_specific_guidance_keeps_saved_advice_immutable(self):
        recommendation=dict(methodology_version='cdss-guidance-v2',rule_key='review_file_origin',
            action_text='Validate origin.',rationale='Source requires review.',evidence_snapshot=json.dumps({'archive_evidence_ids':[8]}))
        original=dict(recommendation)
        investigation={'findings':[{'finding_key':'file_process_events','finding_status':'observed',
            'finding_value':json.dumps([{'kind':'file','alert_id':-8,'file_path':'C:/Temp/observed.ps1'}])}]}
        result=recommendation_presentation(recommendation,None,[],None,investigation)
        self.assertIn('C:/Temp/observed.ps1',result['display_action'])
        self.assertIn('parent process',result['display_action'])
        self.assertEqual(recommendation,original)


class CrossAssetAuditTests(unittest.TestCase):
    def test_local_and_nonhost_addresses_cannot_be_cross_host_pivots(self):
        for value in ('127.0.0.1','::1','::ffff:127.0.0.1','0.0.0.0','::','224.0.0.1','169.254.1.2','fe80::1','255.255.255.255','invalid'):
            with self.subTest(value=value): self.assertIsNone(_cross_address(value))
        self.assertEqual(str(_cross_address('::ffff:10.10.10.20')),'10.10.10.20')
        client=Mock()
        now=datetime.now(timezone.utc)
        with self.assertRaises(ArchiveUnavailable):
            _query_cross_asset(client,{'agent_id':'002'},{'source_ip':'127.0.0.1','username':'Administrator'},now,now,1,'timestamp','agent.id')
        client.search_documents.assert_not_called()

    def test_windows_aliases_and_cap_metadata_with_deterministic_trigger_order(self):
        client=Mock()
        def caps(name,kind):return {kind:{'type':kind,'searchable':True,'aggregatable':True},'unmapped':{'type':'unmapped','searchable':False}}
        client.field_capabilities.return_value={'indices':['wazuh-archives-4.x-2026.10.09'],'fields':{
            'data.win.eventdata.ipAddress':caps('ip','ip'),
            'data.win.eventdata.targetUserName':caps('account','keyword')}}
        hit={'_index':'wazuh-archives-4.x-2026.10.09','_id':'real-shaped',
             '_source':{'timestamp':'2026-10-09T07:00:00Z','agent':{'id':'003'},
                'data':{'win':{'system':{'eventID':'4624'},'eventdata':{'ipAddress':'10.10.10.20','targetUserName':'Administrator'}}}}}
        client.search_documents.return_value={'hits':{'total':{'value':2,'relation':'eq'},'hits':[hit]},'_shards':{'failed':0}}
        trigger=datetime(2026,10,9,7,tzinfo=timezone.utc)
        args=(client,{'agent_id':'002','first_seen_utc':trigger,'last_seen_utc':trigger},
              {'source_ip':'10.10.10.20','username':'Administrator'},trigger-timedelta(minutes=5),trigger+timedelta(minutes=5),1,'timestamp','agent.id')
        evidence,total,truncated=_query_cross_asset(*args)
        self.assertEqual((len(evidence),total,truncated),(1,2,True))
        self.assertEqual(evidence[0]['selected_fields']['username_source_field'],'data.win.eventdata.targetUserName')
        payload=client.search_documents.call_args.args[0]
        encoded=json.dumps(payload)
        self.assertIn('data.win.eventdata.ipAddress',encoded)
        self.assertIn('data.win.eventdata.targetUserName',encoded)
        self.assertIn('_script',payload['sort'][0])
        self.assertEqual(payload['size'],1)
        client.search_documents.return_value['hits']['total']=1
        self.assertFalse(_query_cross_asset(*args)[2])
        client.search_documents.return_value['hits']['hits'][0]['_source']['data']['win']['eventdata']['targetUserName']='different'
        from app.services.archive_evidence import ArchiveInvalid
        with self.assertRaises(ArchiveInvalid): _query_cross_asset(*args)


if __name__=='__main__': unittest.main()
