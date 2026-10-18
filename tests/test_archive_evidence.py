"""Grouped-alert archive retrieval: bounded query, provenance, safety and UI."""

import json
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import Mock, patch

import test_alert_grouping as fixtures
from run import app
from app.database.archive_evidence import migrate_archive_evidence
from app.services.archive_evidence import start_group_archive_retrieval
from app.services.contextual_risk import assess_investigation
from app.services.wazuh_indexer import WazuhIndexerError


CAPABILITIES = {
    'indices': ['wazuh-archives-4.x-2026.10.09'],
    'fields': {
        'timestamp': {'date': {'type': 'date', 'searchable': True, 'aggregatable': True}},
        'agent.id': {'keyword': {'type': 'keyword', 'searchable': True, 'aggregatable': True}},
    },
}


def hit(document_id, timestamp, agent='001', **data):
    return {
        '_index': 'wazuh-archives-4.x-2026.10.09', '_id': document_id,
        '_source': {'timestamp': timestamp, 'agent': {'id': agent, 'name': 'WIN-001'},
                    'decoder': {'name': 'windows_eventchannel'},
                    'data': data, 'full_log': 'DO-NOT-COPY-RAW-ARCHIVE'},
    }


class ArchiveEvidenceTests(unittest.TestCase):
    setUp = fixtures.AlertGroupingTests.setUp
    tearDown = fixtures.AlertGroupingTests.tearDown
    add_alert = fixtures.AlertGroupingTests.add_alert
    client = fixtures.AlertGroupingTests.client

    def enabled_connector(self):
        with self.db:
            return self.db.execute('''INSERT INTO siem_connections
                (name,connector_type,base_url,port,index_pattern,username,
                 encrypted_password,verify_tls,is_enabled,status)
                VALUES('fixture-source','wazuh_indexer','https://fixture.invalid',9200,
                       'wazuh-alerts-*','fixture-reader',X'01',1,1,'connected')''').lastrowid

    def retrieve(self, alert_id, *, hits=None, total=None, capabilities=CAPABILITIES,
                 search_error=None, search=None):
        client = Mock()
        client.field_capabilities.return_value = capabilities
        client.search_documents.return_value = {
            'hits': {'total': {'value': len(hits or []) if total is None else total,
                               'relation': 'eq'}, 'hits': hits or []},
            '_shards': {'failed': 0},
        }
        if search_error or search:
            client.search_documents.side_effect = search_error or search
        adapter = Mock(client=client)
        with (patch('app.services.archive_evidence.create_connector', return_value=adapter) as create,
              patch('app.services.archive_evidence.unprotect_secret', return_value='fixture-secret')):
            with app.app_context():
                execution_id = start_group_archive_retrieval(alert_id)
        return execution_id, client, create

    def test_group_trigger_window_connector_query_provenance_and_no_risk(self):
        connector_id = self.enabled_connector()
        first_id, _ = self.add_alert('trigger-first', 0, mitre=['T1110'])
        last_id, _ = self.add_alert('trigger-last', 5, mitre=['T1110'])
        before_alerts = self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        execution_id, client, create = self.retrieve(last_id, hits=[
            hit('archive-1', '2026-10-09T07:02:00Z', srcip='192.0.2.10', srcuser='alice'),
        ])
        case_id = self.db.execute('SELECT incident_id FROM investigations WHERE id=?',
                                  (execution_id,)).fetchone()[0]
        config = create.call_args.kwargs
        self.assertEqual(config['base_url'], 'https://fixture.invalid:9200')
        self.assertEqual(config['username'], 'fixture-reader')
        self.assertEqual(config['index_name'], 'wazuh-archives-*')
        self.assertTrue(config['verify_tls'])
        self.assertEqual(connector_id, self.db.execute(
            'SELECT connector_id FROM investigation_archive_runs WHERE investigation_id=?',
            (execution_id,)).fetchone()[0])
        payload = client.search_documents.call_args.args[0]
        self.assertEqual(payload['size'], 200)
        self.assertEqual(payload['query']['bool']['filter'], [
            {'term': {'agent.id': '001'}},
            {'range': {'timestamp': {'gte': '2026-10-09T06:50:00+00:00',
                                     'lte': '2026-10-09T07:15:00+00:00'}}},
        ])
        self.assertEqual(payload['sort'][0]['_script']['order'], 'asc')
        self.assertEqual(payload['sort'][1:], [
            {'timestamp': {'order': 'asc'}}, {'_index': {'order': 'asc'}},
            {'_id': {'order': 'asc'}},
        ])
        self.assertNotIn('minimum_rule_level', json.dumps(payload))
        self.assertIn('rule.level', payload['_source'])
        self.assertNotIn('full_log', payload['_source'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], before_alerts)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0], 0)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_findings').fetchone()[0], 0)
        self.assertEqual([row[0] for row in self.db.execute('''SELECT alert_id FROM investigation_archive_triggers
            WHERE investigation_id=? ORDER BY alert_id''', (execution_id,))], [first_id, last_id])
        run = self.db.execute('SELECT * FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution_id,)).fetchone()
        self.assertEqual((run['group_occurrences'], run['retrieval_status'], run['retrieved_count'],
                          run['total_hits'], run['truncated']), (2, 'available', 1, 1, 0))
        self.assertEqual(run['asset_name_snapshot'], 'lab')
        self.assertEqual(json.loads(run['pivots_json'])['mitre_ids'], ['T1110'])
        evidence = self.db.execute('SELECT * FROM investigation_archive_evidence').fetchone()
        self.assertEqual((evidence['source_type'], evidence['source_index'],
                          evidence['source_document_id'], evidence['agent_id']),
                         ('wazuh_archive', 'wazuh-archives-4.x-2026.10.09', 'archive-1', '001'))
        self.assertNotIn('DO-NOT-COPY-RAW-ARCHIVE', evidence['selected_fields_json'])
        self.assertNotIn('fixture-secret', evidence['selected_fields_json'])
        with self.assertRaises(ValueError):
            assess_investigation(case_id, execution_id)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM risk_assessments').fetchone()[0], 0)
        analyst = self.client()
        html = analyst.get(f'/investigations/archive/{execution_id}').data.decode()
        self.assertIn('Supporting Wazuh Evidence', html)
        self.assertIn('archive-1', html)
        self.assertIn('wazuh-archives-4.x-2026.10.09', html)
        self.assertIn(f'/alerts/{first_id}', html)
        self.assertIn(f'/alerts/{last_id}', html)
        self.assertNotIn('DO-NOT-COPY-RAW-ARCHIVE', html)
        case_html = analyst.get(f'/incidents/{case_id}').data.decode()
        self.assertIn('Supporting Evidence', case_html)
        self.assertIn('Investigation Findings', case_html)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_zero_result_is_not_benign_and_does_not_create_findings(self):
        self.enabled_connector()
        alert_id, _ = self.add_alert('archive-empty', 0)
        execution_id, _, _ = self.retrieve(alert_id, hits=[], total=0)
        row = self.db.execute('SELECT retrieval_status,retrieved_count,truncated FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution_id,)).fetchone()
        self.assertEqual(tuple(row), ('empty', 0, 0))
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_archive_evidence').fetchone()[0], 0)
        analyst = self.client()
        html = analyst.get(f'/investigations/archive/{execution_id}').data.decode()
        self.assertIn('No supporting Wazuh archive events were found', html)
        self.assertIn('does not mean the activity was benign', html)

    def test_missing_connector_and_mapping_are_unavailable(self):
        alert_id, _ = self.add_alert('archive-no-connector', 0)
        with app.app_context():
            execution_id = start_group_archive_retrieval(alert_id)
        row = self.db.execute('SELECT retrieval_status FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution_id,)).fetchone()
        self.assertEqual(row[0], 'unavailable')
        self.assertEqual(self.db.execute('SELECT status FROM investigations WHERE id=?',
                                        (execution_id,)).fetchone()[0], 'failed')
        self.assertIn('archive evidence is currently unavailable',
                      self.client().get(f'/investigations/archive/{execution_id}').data.decode())

        self.enabled_connector()
        other_id, _ = self.add_alert('archive-no-mapping', 1)
        execution_id, client, _ = self.retrieve(other_id, capabilities={
            'indices': ['wazuh-archives-4.x-2026.10.09'], 'fields': {}
        })
        self.assertEqual(self.db.execute('SELECT retrieval_status FROM investigation_archive_runs WHERE investigation_id=?',
                                         (execution_id,)).fetchone()[0], 'unavailable')
        client.search_documents.assert_not_called()

    def test_agent_000_unmapped_asset_works_and_query_failure_is_preserved(self):
        self.enabled_connector()
        manager_id, _ = self.add_alert('manager-archive', 0, agent='000')
        execution_id, client, _ = self.retrieve(manager_id, hits=[
            hit('manager-event', '2026-10-09T07:01:00Z', agent='000')
        ])
        payload = client.search_documents.call_args.args[0]
        self.assertEqual(payload['query']['bool']['filter'][0], {'term': {'agent.id': '000'}})
        row = self.db.execute('SELECT asset_id,asset_criticality_snapshot,retrieval_status FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution_id,)).fetchone()
        self.assertEqual(tuple(row), (None, None, 'available'))
        analyst = self.client()
        html = analyst.get(f'/investigations/archive/{execution_id}').data.decode()
        self.assertIn('Wazuh Manager (agent 000)', html)
        self.assertIn('Not mapped', html)

        failed_id, _, _ = self.retrieve(manager_id, search_error=WazuhIndexerError(
            'Network connection failed. Check SIEM address, port, firewall, and routing.'))
        self.assertEqual(self.db.execute('SELECT retrieval_status FROM investigation_archive_runs WHERE investigation_id=?',
                                         (failed_id,)).fetchone()[0], 'unavailable')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_archive_evidence WHERE investigation_id=?',
                                         (failed_id,)).fetchone()[0], 0)
        self.assertNotIn('fixture-secret',
                         analyst.get(f'/investigations/archive/{failed_id}').data.decode())

    def test_cap_truncation_chronology_and_configurable_buffer(self):
        self.enabled_connector()
        first_id, _ = self.add_alert('cap-first', 0)
        self.add_alert('cap-last', 5)
        app.config['INVESTIGATION_EVIDENCE_BUFFER_MINUTES'] = '3'
        app.config['INVESTIGATION_MAX_ARCHIVE_EVENTS'] = '2'
        try:
            execution_id, client, _ = self.retrieve(first_id, hits=[
                hit('later', '2026-10-09T07:04:00Z'),
                hit('earlier', '2026-10-09T07:01:00Z'),
            ], total=3)
        finally:
            app.config['INVESTIGATION_EVIDENCE_BUFFER_MINUTES'] = '10'
            app.config['INVESTIGATION_MAX_ARCHIVE_EVENTS'] = '200'
        payload = client.search_documents.call_args.args[0]
        self.assertEqual(payload['size'], 2)
        self.assertEqual(payload['query']['bool']['filter'][1]['range']['timestamp'],
                         {'gte': '2026-10-09T06:57:00+00:00',
                          'lte': '2026-10-09T07:08:00+00:00'})
        row = self.db.execute('SELECT retrieved_count,total_hits,truncated FROM investigation_archive_runs WHERE investigation_id=?',
                              (execution_id,)).fetchone()
        self.assertEqual(tuple(row), (2, 3, 1))
        html = self.client().get(f'/investigations/archive/{execution_id}').data.decode()
        self.assertLess(html.index('Document earlier'), html.index('Document later'))
        self.assertIn('Results truncated', html)

    def test_alternative_mapped_fields_and_malformed_result_fail_closed(self):
        self.enabled_connector()
        alert_id, _ = self.add_alert('alternative-fields', 0)
        capabilities = {'indices': ['wazuh-archives-4.x-2026.10.09'], 'fields': {
            '@timestamp': {'date': {'searchable': True, 'aggregatable': True}},
            'agent.id.keyword': {'keyword': {'searchable': True, 'aggregatable': True}},
        }}
        event = hit('alternate', '2026-10-09T07:01:00Z')
        event['_source']['@timestamp'] = event['_source'].pop('timestamp')
        execution_id, client, _ = self.retrieve(alert_id, hits=[event], capabilities=capabilities)
        payload = client.search_documents.call_args.args[0]
        self.assertEqual(payload['query']['bool']['filter'][0], {'term': {'agent.id.keyword': '001'}})
        self.assertIn('@timestamp', payload['query']['bool']['filter'][1]['range'])
        self.assertEqual(self.db.execute('SELECT retrieval_status FROM investigation_archive_runs WHERE investigation_id=?',
                                         (execution_id,)).fetchone()[0], 'available')

        bad = hit('wrong-agent', '2026-10-09T07:01:00Z', agent='002')
        failed_id, _, _ = self.retrieve(alert_id, hits=[bad])
        self.assertEqual(self.db.execute('SELECT retrieval_status FROM investigation_archive_runs WHERE investigation_id=?',
                                         (failed_id,)).fetchone()[0], 'failed')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_archive_evidence WHERE investigation_id=?',
                                         (failed_id,)).fetchone()[0], 0)

    def test_explicit_post_requires_auth_and_csrf(self):
        self.enabled_connector()
        alert_id, _ = self.add_alert('post-trigger', 0)
        path = f'/alerts/groups/{alert_id}/investigate'
        self.assertEqual(app.test_client().post(path).status_code, 302)
        client = self.client()
        self.assertEqual(client.get(path).status_code, 405)
        self.assertEqual(client.post(path).status_code, 400)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_archive_runs').fetchone()[0], 0)
        fake = Mock()
        fake.field_capabilities.return_value = CAPABILITIES
        fake.search_documents.return_value = {'hits': {'total': {'value': 0, 'relation': 'eq'}, 'hits': []}}
        with (patch('app.services.archive_evidence.create_connector', return_value=Mock(client=fake)),
              patch('app.services.archive_evidence.unprotect_secret', return_value='fixture-secret')):
            response = client.post(path, data={'csrf_token': 'test-token'})
        self.assertEqual(response.status_code, 302)
        self.assertIn('/incidents/', response.headers['Location'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_archive_runs').fetchone()[0], 1)

    def test_trigger_near_evidence_survives_more_than_200_earlier_events(self):
        self.enabled_connector()
        first_id, _ = self.add_alert('crowded-first', 0)
        self.add_alert('crowded-last', 5)
        base = datetime(2026, 10, 9, 7, tzinfo=timezone.utc)
        documents = [hit(f'early-{n:03}', (base - timedelta(minutes=9)
                         + timedelta(seconds=n)).isoformat()) for n in range(250)]
        documents += [hit('near-first', (base + timedelta(seconds=1)).isoformat()),
                      hit('near-last', (base + timedelta(minutes=5, seconds=1)).isoformat())]

        def search(payload):
            # Small transport fixture honors the requested ordering, so the old
            # earliest-first query actually loses both decisive near-trigger hits.
            ordered = sorted(documents, key=lambda h: (h['_source']['timestamp'], h['_id']))
            if '_script' in payload['sort'][0]:
                spec = payload['sort'][0]['_script']
                self.assertIn('Math.min', spec['script']['source'])
                self.assertIn('Math.abs', spec['script']['source'])
                p = spec['script']['params']
                def rank(h):
                    t = int(datetime.fromisoformat(h['_source']['timestamp']).timestamp() * 1000)
                    return (min(abs(t - p['first']), abs(t - p['last'])), t, h['_index'], h['_id'])
                ordered.sort(key=rank)
            self.assertEqual(payload['size'], 200)
            return {'hits': {'total': {'value': len(documents), 'relation': 'eq'},
                             'hits': ordered[:payload['size']]}, '_shards': {'failed': 0}}

        execution_id, client, _ = self.retrieve(first_id, search=search)
        ids = {r[0] for r in self.db.execute('SELECT source_document_id FROM '
            'investigation_archive_evidence WHERE investigation_id=?', (execution_id,))}
        self.assertTrue({'near-first', 'near-last'} <= ids)
        self.assertEqual(len(ids), 200)
        self.assertEqual(tuple(self.db.execute('SELECT retrieved_count,total_hits,truncated '
            'FROM investigation_archive_runs WHERE investigation_id=?', (execution_id,)).fetchone()),
            (200, 252, 1))
        client.search_documents.assert_called_once()

    def test_archive_window_and_trigger_ranking_normalize_source_offsets(self):
        self.enabled_connector()
        alert_id, _ = self.add_alert('offset-first', 0, timestamp='2026-10-09T12:30:00+0530')
        self.add_alert('offset-last', 5, timestamp='2026-10-09T08:05:00+01:00')
        execution, client, _ = self.retrieve(alert_id, hits=[hit('offset-observation',
            '2026-10-09T08:01:00+01:00')])
        payload = client.search_documents.call_args.args[0]
        self.assertEqual(payload['query']['bool']['filter'][1]['range']['timestamp'],
            {'gte': '2026-10-09T06:50:00+00:00', 'lte': '2026-10-09T07:15:00+00:00'})
        params = payload['sort'][0]['_script']['script']['params']
        self.assertEqual(params['field'], 'timestamp')
        self.assertEqual(params['first'], int(datetime(2026,10,9,7,tzinfo=timezone.utc).timestamp()*1000))
        self.assertEqual(params['last']-params['first'], 300000)
        self.assertEqual(self.db.execute('SELECT event_timestamp FROM investigation_archive_evidence '
            'WHERE investigation_id=?',(execution,)).fetchone()[0], '2026-10-09T07:01:00+00:00')

    def test_naive_or_invalid_source_time_is_not_assumed_to_be_host_time(self):
        from app.services.incident_correlation import event_time
        for value in (None, '', 'bad', '2026-10-09T07:00:00'):
            self.assertIsNone(event_time(value))
        self.assertEqual(event_time('2026-10-09T12:30:00+0530'),
                         event_time('2026-10-09T07:00:00Z'))

    def test_idempotent_migration_and_relational_integrity(self):
        alert_id, _ = self.add_alert('migration-source', 0)
        before = self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        with self.db:
            migrate_archive_evidence(self.db)
            migrate_archive_evidence(self.db)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0], before)
        self.assertIsNotNone(self.db.execute('SELECT id FROM alerts WHERE id=?', (alert_id,)).fetchone())
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])


if __name__ == '__main__':
    unittest.main()
