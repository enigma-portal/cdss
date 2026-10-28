"""Offline process-instance, ordering, coverage and decisive-only UX regressions."""
import copy
import json
import unittest

from app.services.archive_evidence import archive_coverage
from app.services.contextual_risk import _file_state, _file_related, _confidence
from app.services.evidence_progression import evidence_progression
from app.services.investigation import _file_events
from app.services.playbook_registry import FILE_PROCESS


class CausalEvidenceTests(unittest.TestCase):
    def event(self, identifier, kind, second, pid='624', guid='instance', agent='003'):
        fields = dict(provider_name='Microsoft-Windows-Sysmon', channel='Microsoft-Windows-Sysmon/Operational',
                      utc_time=f'2026-10-23 07:42:{second:06.3f}', process_id=pid,
                      process_guid=guid, process_name='C:/Windows/powershell.exe', username='alice',
                      event_id={'process':'1','file':'11','network':'3'}[kind])
        if kind == 'process': fields['command_line'] = 'powershell.exe -Command fixture'
        if kind == 'file': fields['file_path'] = 'C:/Temp/fixture.txt'
        if kind == 'network': fields.update(destination_ip='192.0.2.10', destination_port='8080', source_ip='192.0.2.20')
        return dict(id=identifier, event_timestamp='2026-10-23T07:42:33Z', source_fields=fields,
                    agent_id=agent, asset_id=1, username='alice', source_ip=fields.get('source_ip'), rule_groups=None)

    def findings(self, evidence, coverage=None):
        return dict(file_process_events=dict(value=_file_events(evidence.values()), status='observed', refs=set(evidence)),
                    archive_coverage=dict(value=coverage, status='unavailable'))

    def test_matching_guid_and_source_time_resolve_equal_receipt_times(self):
        evidence={1:self.event(1,'process',32.502),2:self.event(2,'file',32.606),3:self.event(3,'network',38.522)}
        state,ids,_=_file_state(self.findings(evidence),evidence)
        self.assertEqual((state,ids),('T4',[1,2,3]))

    def test_conflicting_pid_or_guid_and_cross_agent_never_link(self):
        for changes in (dict(pid='7156'),dict(guid='different'),dict(agent='004')):
            evidence={1:self.event(1,'process',32),2:self.event(2,'file',33,**changes)}
            self.assertEqual(_file_state(self.findings(evidence),evidence)[0],'T1')

    def test_file_before_process_never_progresses_even_with_matching_guid(self):
        evidence={1:self.event(1,'process',33),2:self.event(2,'file',32),3:self.event(3,'network',38)}
        self.assertEqual(_file_state(self.findings(evidence),evidence)[0],'T1')

    def test_pid_fallback_requires_bounded_time_and_known_agent(self):
        evidence={1:self.event(1,'process',32,guid=None),2:self.event(2,'file',33,guid=None)}
        self.assertEqual(_file_state(self.findings(evidence),evidence)[0],'T3')
        evidence[2]['source_fields']['utc_time']='2026-10-23 08:42:33'
        self.assertEqual(_file_state(self.findings(evidence),evidence)[0],'T1')

    def test_path_and_user_without_instance_identifiers_are_insufficient(self):
        evidence={1:self.event(1,'process',32,pid=None,guid=None),2:self.event(2,'file',33,pid=None,guid=None)}
        self.assertEqual(_file_state(self.findings(evidence),evidence)[0],'T1')

    def test_all_pairs_evaluated_before_choosing_progression(self):
        evidence={-100:self.event(-100,'process',30,pid='111',guid='other'),
                  -101:self.event(-101,'file',31,pid='111',guid='other'),
                  -2:self.event(-2,'process',32),1:self.event(1,'file',33),-3:self.event(-3,'network',38)}
        self.assertEqual(_file_state(self.findings(evidence),evidence)[:2],('T4',[-3,-2,1]))

    def test_unrelated_later_network_does_not_cause_t4(self):
        evidence={1:self.event(1,'process',32),2:self.event(2,'file',33),3:self.event(3,'network',38,pid='123',guid='background')}
        self.assertEqual(_file_state(self.findings(evidence),evidence)[:2],('T3',[1,2]))

    def test_coverage_and_confidence_distinguish_partial_from_unavailable(self):
        evidence={1:self.event(1,'process',32),2:self.event(2,'file',33),3:self.event(3,'network',38)}
        run=dict(retrieval_status='available',retrieved_count=200,total_hits=288,truncated=1)
        self.assertEqual(archive_coverage(run),'partial')
        findings=self.findings(evidence,run)
        self.assertEqual(_confidence('T4',[1,2,3],evidence,findings,{'id':1},FILE_PROCESS)[0],'medium')
        findings['archive_coverage']['value']=dict(retrieval_status='failed')
        self.assertEqual(_confidence('T4',[1,2,3],evidence,findings,{'id':1},FILE_PROCESS)[0],'low')
        self.assertEqual(archive_coverage(dict(retrieval_status='empty',truncated=0)),'complete')
        self.assertEqual(archive_coverage(None),'unavailable')

    def test_progression_uses_saved_decisive_ids_and_preserves_strings(self):
        evidence={1:self.event(1,'process',32),2:self.event(2,'file',33),3:self.event(3,'network',38),4:self.event(4,'network',39,pid='99',guid='background')}
        original=copy.deepcopy(evidence)
        assessment=dict(inputs_snapshot=json.dumps(dict(decisive_evidence_ids=[1,2,3])))
        investigation=dict(findings=[dict(finding_key='linked_alert_evidence',finding_value=json.dumps(list(evidence.values())))])
        view=evidence_progression(assessment,investigation)
        self.assertEqual([r['alert_id'] for r in view['decisive']],[1,2,3])
        self.assertEqual([r['alert_id'] for r in view['background']],[4])
        self.assertIn('matching ProcessGuid',view['decisive'][1]['relation'])
        self.assertEqual(evidence,original)

    def test_historical_invalid_chain_is_not_presented_as_linked(self):
        evidence={1:self.event(1,'process',32),2:self.event(2,'file',30,pid='99',guid='old')}
        assessment=dict(inputs_snapshot=json.dumps(dict(decisive_evidence_ids=[1,2])))
        investigation=dict(findings=[dict(finding_key='linked_alert_evidence',finding_value=json.dumps(list(evidence.values())))])
        view=evidence_progression(assessment,investigation)
        self.assertEqual(view['decisive'][0]['relation'],'No process-instance relationship established.')
