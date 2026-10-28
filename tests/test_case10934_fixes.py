"""Offline regressions for the verified case audit; no main-DB fixtures."""
import copy
import json
import unittest
from datetime import datetime, timezone
from itertools import combinations
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace

import test_archive_evidence as archive_fixtures
import test_alert_grouping as group_fixtures
from run import app
from app.services.archive_evidence import _selected, _cross_address
from app.services.contextual_risk import _file_related, _file_state
from app.services.evidence_context import windows_path_equal, network_label
from app.services.investigation import _file_events, _archive_row_as_alert, _remote_events
from app.services.alert_view import list_alerts, group_context


class EvidenceTests(unittest.TestCase):
    def test_windows_comparison_preserves_evidence(self):
        left = r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
        right = r'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe'
        self.assertTrue(windows_path_equal(left, right))
        self.assertTrue(windows_path_equal(left, right.replace('\\', '/')))
        self.assertFalse(windows_path_equal(left, right.replace('powershell', 'other')))
        self.assertFalse(windows_path_equal('/bin/Tool', '/bin/tool'))
        self.assertEqual(right, r'C:\WINDOWS\System32\WindowsPowerShell\v1.0\powershell.exe')

    def case_observations(self):
        # Exact categories, image spelling, identities and ordering from execution 79.
        events = []
        for aid, kind, time in [(-3488,'process','22.007'),(-3489,'file','22.013'),
                                (-3495,'process','32.563'),(22653,'file','32.591')]:
            fields = {'event_id':'1' if kind=='process' else '11',
                'process_name':('C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
                                if kind=='process' else
                                'C:/WINDOWS/System32/WindowsPowerShell/v1.0/powershell.exe'),
                'username':r'CORP\Administrator',
                'rule_groups':['sysmon']}
            fields.update({'command_line':'powershell -NoProfile -Command Set-Content'}
                          if kind=='process' else {'file_path':f'C:/Temp/PolicyTest-{aid}.ps1'})
            events.append({'id':aid,'asset_id':6,'agent_id':'003','username':fields['username'],
                'source_ip':None,'destination_ip':None,'source_fields':fields,
                'rule_groups':['sysmon'],'event_timestamp':f'2026-10-21T07:42:{time}+00:00'})
        return {a['id']:a for a in events}

    def test_case_relationship_and_actual_state(self):
        evidence = self.case_observations()
        before = copy.deepcopy(evidence)
        events = _file_events(evidence.values())
        pairs = [(a,b) for a,b in combinations(events,2)
                 if a['kind']!=b['kind'] and _file_related(a,b,evidence)]
        # The old fixture has path/account context but no process instance IDs.
        self.assertEqual(len(pairs),0)
        findings = {'file_process_events':{'value':events,'status':'observed',
                    'refs':{a['alert_id'] for a in events}}}
        self.assertEqual(_file_state(findings,evidence)[0],'T1')
        self.assertEqual(evidence,before)

    def test_conflicts_still_reject(self):
        evidence = self.case_observations()
        # Synthetic process identity for this conflict test, not recovered logs.
        for row in evidence.values():
            row['source_fields']['process_id']='fixture-pid'
        events = {a['alert_id']:a for a in _file_events(evidence.values())}
        a,b=events[-3495],events[22653]
        self.assertTrue(_file_related(a,b,evidence))
        b['username']='other'
        self.assertFalse(_file_related(a,b,evidence))
        b['username']=a['username']
        evidence[-3495]['source_ip']='192.0.2.1'
        evidence[22653]['source_ip']='192.0.2.2'
        self.assertFalse(_file_related(a,b,evidence))

    def source(self, event_id='3', provider='Microsoft-Windows-Sysmon'):
        return {'data':{'win':{'system':{'eventID':event_id,'providerName':provider,
            'channel':'Microsoft-Windows-Sysmon/Operational'},'eventdata':{
            'image':'C:/Windows/powershell.exe','user':r'CORP\Administrator',
            'sourceIp':'10.10.10.20','destinationIp':'10.10.10.10','destinationPort':'8080',
            'processId':'8560','processGuid':'{fixture-guid}',
            'utcTime':'2026-10-21 07:42:34.249'}}}}

    def archive_alert(self, source):
        row={'id':1,'selected_fields_json':json.dumps(_selected(source)),
            'source_index':'wazuh-archives-4.x-fixture','source_document_id':'original-doc',
            'event_timestamp':'2026-10-21T07:42:40.715+00:00','agent_id':'003',
            'short_summary':'windows_eventchannel'}
        return _archive_row_as_alert(row,{'asset_id':6},'003')

    def test_archive_only_sysmon_network_and_provenance(self):
        alert=self.archive_alert(self.source())
        fields=alert['source_fields']
        self.assertEqual(_file_events([alert])[0]['kind'],'network')
        self.assertEqual(fields['destination_ip'],'10.10.10.10')
        self.assertEqual(fields['source_ip'],'10.10.10.20')
        for field in ('event_id','process_name','username','destination_port','process_id',
                      'process_guid','utc_time','provider_name','channel'):
            self.assertTrue(fields[field])
        self.assertEqual(alert['source_provenance']['source_document_id'],'original-doc')
        self.assertEqual(alert['event_timestamp'],'2026-10-21T07:42:40.715+00:00')
        self.assertIsNone(alert['rule_groups'])

    def test_unrelated_event3_and_security4688_are_not_sysmon(self):
        for event_id,provider in [('3','Other-Provider'),('4688','Microsoft-Windows-Security-Auditing')]:
            alert=self.archive_alert(self.source(event_id,provider))
            self.assertEqual(_file_events([alert]),[])
            self.assertTrue(alert['source_fields']['process_name'])

    def test_progression_requires_later_related_network(self):
        evidence=self.case_observations()
        # Synthetic instance linkage tests progression separately from the saved
        # case fixture, whose missing process IDs cannot establish this linkage.
        for row in evidence.values():
            row['source_fields'].update(process_id='8560',process_guid='{fixture-guid}')
        source=self.source()
        source['data']['win']['eventdata']['image']='C:/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'
        network=self.archive_alert(source)
        evidence[network['id']]=network
        def state():
            events=_file_events(evidence.values())
            return _file_state({'file_process_events':{'value':events,'status':'observed',
                'refs':{a['alert_id'] for a in events}}},evidence)[0]
        self.assertEqual(state(),'T4')
        network['source_fields']['utc_time']='2026-10-21 07:42:20.000'
        self.assertEqual(state(),'T3')
        network['source_fields']['utc_time']='2026-10-21 07:42:34.249'
        network['source_fields']['username']='different'
        self.assertEqual(state(),'T3')

    def test_loopback_is_local_and_cannot_pivot(self):
        for address in ('::1','127.0.0.1','127.23.45.67'):
            self.assertIn('loopback/local-host',network_label(address))
            self.assertIsNone(_cross_address(address))
            alert={'id':1,'agent_id':'003','source_ip':address,'username':'alice',
                'rule_groups':['sshd','authentication_success'],'source_fields':{}}
            self.assertEqual(_remote_events([alert]),[])

    def test_blank_evidence_checks_are_not_bullets(self):
        source=Path('templates/incident_detail.html').read_text(encoding='utf-8')
        fragment=source[source.index('  {% set checks ='):source.index('{% endif %}',
            source.index('  {% set checks ='))+len('{% endif %}')]
        with app.app_context():
            html=app.jinja_env.from_string(fragment).render(selected_playbook=SimpleNamespace(
                evidence_requests=[None,{},SimpleNamespace(label=None),
                    SimpleNamespace(label='  '),SimpleNamespace(label='Inspect process')]))
        self.assertEqual(html.count('<li>'),1)
        self.assertIn('<li>Inspect process</li>',html)


class ArchiveStorageTests(unittest.TestCase):
    setUp=archive_fixtures.ArchiveEvidenceTests.setUp
    tearDown=archive_fixtures.ArchiveEvidenceTests.tearDown
    add_alert=archive_fixtures.ArchiveEvidenceTests.add_alert
    enabled_connector=archive_fixtures.ArchiveEvidenceTests.enabled_connector
    retrieve=archive_fixtures.ArchiveEvidenceTests.retrieve

    def test_new_archive_fields_survive_storage_and_reload(self):
        self.enabled_connector()
        aid,_=self.add_alert('trigger',0)
        source=EvidenceTests().source()
        source.update(timestamp='2026-10-09T07:00:01Z',agent={'id':'001'})
        run,client,_=self.retrieve(aid,hits=[{'_index':'wazuh-archives-4.x-2026.10.09',
            '_id':'network-original','_source':source}])
        row=self.db.execute('select * from investigation_archive_evidence where investigation_id=?',
                            (run,)).fetchone()
        fields=json.loads(row['selected_fields_json'])
        self.assertEqual(fields['destination_port'],'8080')
        self.assertEqual(fields['process_guid'],'{fixture-guid}')
        self.assertEqual(fields['utc_time'],'2026-10-21 07:42:34.249')
        alert=_archive_row_as_alert(row,{'asset_id':1},'001')
        self.assertEqual(_file_events([alert])[0]['kind'],'network')
        self.assertEqual(alert['source_provenance']['source_document_id'],'network-original')
        self.assertEqual(client.search_documents.call_args.args[0]['size'],200)
        self.assertIn('data.win.system.providerName',client.search_documents.call_args.args[0]['_source'])
        self.assertEqual(self.db.execute('PRAGMA integrity_check').fetchone()[0],'ok')
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_saved_evidence_rerun_adds_history_without_collection(self):
        from app.services.investigation import run_investigation
        from app.services.contextual_risk import assess_investigation
        self.enabled_connector()
        aid,_=self.add_alert('trigger',0)
        run,_,_=self.retrieve(aid,hits=[])
        case=self.db.execute('select incident_id from investigations where id=?',(run,)).fetchone()[0]
        first=run_investigation(case)
        assessment=assess_investigation(case,first)
        before=tuple(self.db.execute('select * from risk_assessments where id=?',(assessment,)).fetchone())
        findings=[tuple(r) for r in self.db.execute('select * from investigation_findings where investigation_id=?',(first,))]
        with patch('app.services.archive_evidence.create_connector') as connector:
            second=run_investigation(case)
            assess_investigation(case,second)
            connector.assert_not_called()
        self.assertNotEqual(first,second)
        self.assertEqual(before,tuple(self.db.execute('select * from risk_assessments where id=?',(assessment,)).fetchone()))
        self.assertEqual(findings,[tuple(r) for r in self.db.execute('select * from investigation_findings where investigation_id=?',(first,))])


class QueueTests(unittest.TestCase):
    setUp=group_fixtures.AlertGroupingTests.setUp
    tearDown=group_fixtures.AlertGroupingTests.tearDown
    add_alert=group_fixtures.AlertGroupingTests.add_alert
    client=group_fixtures.AlertGroupingTests.client

    def test_time_filters_use_event_time_and_preserve_groups(self):
        self.add_alert('recent',0)
        self.add_alert('old',-1500,rule='other')
        with app.app_context(), patch('app.services.alert_view.datetime') as clock:
            clock.now.return_value=datetime(2026,10,9,7,10,tzinfo=timezone.utc)
            clock.min=datetime.min
            for period in ('15m','1h','24h'):
                groups,page=list_alerts(self.db,{'period':period,'q':'recent','sort':'latest'})
                self.assertEqual(len(groups),1)
                self.assertEqual(page['period'],period)
        with app.app_context():
            groups,page=list_alerts(self.db,{'period':'custom','from':'2026-10-09T06:59',
                'to':'2026-10-09T07:01','sort':'latest'})
            self.assertEqual(len(groups),1)
            self.assertEqual(page['raw_total'],1)
            self.assertEqual(list_alerts(self.db,{})[1]['raw_total'],2)
            self.assertEqual(list_alerts(self.db,{'period':'custom','from':'bad','to':'bad'})[1]['total'],0)
        response=self.client().get('/alerts?period=custom&from=2026-10-09T06:59&to=2026-10-09T07:01')
        self.assertEqual(response.status_code,200)
        self.assertIn(b'Last 15 minutes',response.data)

    def test_prior_case_link_preserves_membership(self):
        first,_=self.add_alert('earlier',0)
        from app.services.archive_evidence import start_group_archive_retrieval
        with app.app_context():
            run=start_group_archive_retrieval(first)
        case=self.db.execute('select incident_id from investigations where id=?',(run,)).fetchone()[0]
        second,_=self.add_alert('later',2)
        different,_=self.add_alert('different',3,user='bob')
        before=list(self.db.execute('select * from investigation_case_alerts'))
        with app.app_context():
            self.assertEqual(group_context(self.db,second)['prior_matching_case_id'],case)
            self.assertIsNone(group_context(self.db,different)['prior_matching_case_id'])
        self.assertEqual(before,list(self.db.execute('select * from investigation_case_alerts')))
        self.assertIn(b'earlier case membership remains unchanged',
                      self.client().get(f'/alerts/groups/{second}').data)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])
