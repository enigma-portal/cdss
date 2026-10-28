"""Read-only repeated-alert grouping and analyst occurrence provenance."""

from datetime import datetime, timedelta, timezone
import sqlite3
import unittest

import test_contextual_risk as fixtures
from run import app
from app.services.alert_view import group_context, list_alerts
from app.services.archive_evidence import start_group_archive_retrieval
from app.services.contextual_risk import assess_investigation
from app.services.incident_processor import process_alert
from app.services.investigation import run_investigation


BASE_TIME = datetime(2026, 10, 9, 7, 0, tzinfo=timezone.utc)


class AlertGroupingTests(unittest.TestCase):
    setUp = fixtures.ContextualRiskTests.setUp
    tearDown = fixtures.ContextualRiskTests.tearDown
    client = fixtures.ContextualRiskTests.client

    def add_alert(self, name, minute, *, agent='001', rule='5710',
                  source='192.0.2.10', user='alice', destination='198.51.100.10',
                  path=None, target_filename=None, mitre=None, timestamp=None,
                  level=7, firedtimes=None):
        event = {
            'id': name,
            'timestamp': timestamp or (BASE_TIME + timedelta(minutes=minute)).isoformat(),
            'rule': {'id': rule, 'description': 'Authentication failure observed',
                     'level': level, 'groups': ['authentication_failed']},
            'agent': {'id': agent, 'name': 'wazuh' if agent == '000' else 'WIN-' + agent},
            'data': {'srcip': source, 'srcuser': user, 'dstip': destination},
        }
        if path is not None:
            event['syscheck'] = {'path': path}
        if target_filename is not None:
            event['data']['win'] = {'eventdata': {'targetFilename': target_filename}}
        if mitre:
            event['rule']['mitre'] = {'id': mitre}
        if firedtimes is not None:
            event['rule']['firedtimes'] = firedtimes
        case_id = process_alert(event)['incident_id']
        alert_id = self.db.execute(
            'SELECT id FROM alerts WHERE wazuh_alert_id=?', (name,)
        ).fetchone()[0]
        return alert_id, case_id

    def groups(self):
        with app.app_context():
            return list_alerts(self.db, {})

    def context(self, alert_id):
        with app.app_context():
            return group_context(self.db, alert_id)

    def test_ten_repeated_alerts_become_one_group_without_changing_raw_rows(self):
        ids = [self.add_alert(f'repeated-{number}', number)[0] for number in range(10)]
        before = [tuple(row) for row in self.db.execute(
            'SELECT id,wazuh_alert_id,event_timestamp,raw_alert FROM alerts ORDER BY id'
        )]
        groups, pagination = self.groups()
        self.assertEqual((len(groups), pagination['total'], pagination['raw_total']),
                         (1, 1, 10))
        group = groups[0]
        self.assertEqual(group['occurrences'], 10)
        self.assertEqual(group['alert_ids'], ids)
        self.assertEqual(group['representative_alert_id'], ids[-1])
        self.assertEqual(group['first_seen_utc'], BASE_TIME)
        self.assertEqual(group['last_seen_utc'], BASE_TIME + timedelta(minutes=9))
        self.assertEqual(self.context(ids[0])['alert_ids'], ids)
        detail = self.client().get(f'/alerts/groups/{ids[-1]}').data.decode()
        self.assertIn('Occurrence History (10)', detail)
        for number in range(10):
            self.assertIn(f'repeated-{number}', detail)
        self.assertEqual(before, [tuple(row) for row in self.db.execute(
            'SELECT id,wazuh_alert_id,event_timestamp,raw_alert FROM alerts ORDER BY id'
        )])
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_legacy_assessment_does_not_claim_grouped_case_was_investigated(self):
        alert_id, legacy_case = self.add_alert('historical-assessment', 0)
        assessment_run = run_investigation(legacy_case)
        assess_investigation(legacy_case, assessment_run)
        self.assertEqual(self.context(alert_id)['investigation_status'], 'New')
        self.assertFalse(self.context(alert_id)['fully_assessed'])
        self.assertIn('New', self.client().get(f'/alerts/groups/{alert_id}').data.decode())

        with app.app_context():
            retrieval_id = start_group_archive_retrieval(alert_id)
        analyst_case = self.db.execute('SELECT incident_id FROM investigations WHERE id=?',
                                       (retrieval_id,)).fetchone()[0]
        self.assertNotEqual(analyst_case, legacy_case)
        self.assertEqual(self.context(alert_id)['investigation_status'], 'Investigation Started')
        assessed_run = run_investigation(analyst_case)
        assess_investigation(analyst_case, assessed_run)
        self.assertEqual(self.context(alert_id)['investigation_status'], 'Assessed')
        self.assertTrue(self.context(alert_id)['fully_assessed'])

    def test_case_displays_archive_used_by_assessment_not_later_retry(self):
        alert_id, _ = self.add_alert('archive-snapshot', 0)
        with app.app_context():
            first = start_group_archive_retrieval(alert_id)
        analyst_case = self.db.execute('SELECT incident_id FROM investigations WHERE id=?',
                                       (first,)).fetchone()[0]
        assessed_run = run_investigation(analyst_case)
        assess_investigation(analyst_case, assessed_run)
        with app.app_context():
            second = start_group_archive_retrieval(alert_id)
        with self.db:
            self.db.execute('UPDATE investigation_archive_runs SET selection_reason=? WHERE investigation_id=?',
                            ('Selected with assessed evidence', first))
            self.db.execute('UPDATE investigation_archive_runs SET selection_reason=? WHERE investigation_id=?',
                            ('Later retry not yet evaluated', second))
        html = self.client().get(f'/incidents/{analyst_case}').data.decode()
        self.assertIn('Selected with assessed evidence', html)
        self.assertNotIn('Later retry not yet evaluated', html)
        self.assertIn('Latest evidence retrieval unavailable.', html)
        self.assertIn('Last successful assessment:', html)

    def test_fixed_window_and_timezone_offsets_are_handled_by_event_time(self):
        first, _ = self.add_alert('first', 0, timestamp='2026-10-09T08:00:00+0100')
        second, _ = self.add_alert('within', 59)
        third, _ = self.add_alert('outside', 61)
        groups, _ = self.groups()
        self.assertEqual([group['occurrences'] for group in groups], [1, 2])
        self.assertEqual(self.context(first)['alert_ids'], [first, second])
        self.assertEqual(self.context(third)['alert_ids'], [third])
        self.assertEqual(self.context(first)['first_seen_utc'], BASE_TIME)
        app.config['ALERT_GROUP_WINDOW_MINUTES'] = 30
        try:
            self.assertEqual(self.context(first)['alert_ids'], [first])
        finally:
            app.config['ALERT_GROUP_WINDOW_MINUTES'] = '60'

    def test_different_agents_entities_levels_and_paths_never_merge(self):
        self.add_alert('base', 0)
        self.add_alert('different-agent', 0, agent='002')
        self.add_alert('different-source', 0, source='192.0.2.11')
        self.add_alert('different-user', 0, user='bob')
        self.add_alert('different-destination', 0, destination='198.51.100.11')
        self.add_alert('different-path', 0, path='/tmp/example')
        self.add_alert('different-level', 0, level=8)
        groups, pagination = self.groups()
        self.assertEqual((len(groups), pagination['total']), (7, 7))
        self.assertEqual({group['agent_id'] for group in groups}, {'001', '002'})
        self.assertTrue(all(group['occurrences'] == 1 for group in groups))

    def test_priority_sort_uses_same_model_across_pages_not_just_newest(self):
        older_critical, _ = self.add_alert('older-critical', 0, rule='9001', level=13)
        newer_low, _ = self.add_alert('newer-low', 10, rule='9002', level=4)
        default_groups, pagination = self.groups()
        self.assertEqual(pagination['sort'], 'priority')
        self.assertEqual([group['representative_alert_id'] for group in default_groups],
                         [older_critical, newer_low])
        with app.app_context():
            newest, newest_page = list_alerts(self.db, {'sort': 'latest'})
        self.assertEqual(newest_page['sort'], 'latest')
        self.assertEqual([group['representative_alert_id'] for group in newest],
                         [newer_low, older_critical])
        html = self.client().get('/alerts').data.decode()
        self.assertLess(html.index(f'/alerts/groups/{older_critical}'),
                        html.index(f'/alerts/groups/{newer_low}'))
        self.assertIn('Priority and source details', html)

    def test_distinct_sysmon_artifacts_do_not_merge_but_existing_case_is_preserved(self):
        first, _ = self.add_alert('artifact-one', 0, target_filename='C:/Temp/a.zip')
        second, _ = self.add_alert('artifact-two', 1, target_filename='C:/Temp/b.zip')
        repeated, _ = self.add_alert('artifact-one-repeat', 2, target_filename='C:/Temp/a.zip')
        groups, _ = self.groups()
        self.assertEqual(sorted(group['occurrences'] for group in groups), [1, 2])
        self.assertEqual(self.context(first)['alert_ids'], [first, repeated])
        self.assertEqual(self.context(second)['alert_ids'], [second])

        # Simulate historical case membership from the previous, less precise
        # grouping rule in this isolated fixture only; no source row is deleted.
        with app.app_context():
            run_id = start_group_archive_retrieval(first)
        case_id = self.db.execute('SELECT incident_id FROM investigations WHERE id=?',
                                  (run_id,)).fetchone()[0]
        with self.db:
            self.db.execute('''INSERT INTO investigation_case_alerts(case_id,alert_id,ordinal)
                VALUES(?,?,?)''', (case_id, second, 2))
        preserved = self.context(second)
        self.assertTrue(preserved['existing_case_membership'])
        self.assertEqual(set(preserved['alert_ids']), {first, second, repeated})
        html = self.client().get(f'/alerts/groups/{second}').data.decode()
        self.assertIn('They may describe different artifacts', html)
        self.assertIn('3 stored Wazuh alerts', html)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])

    def test_manager_unmapped_and_mapped_asset_remain_distinct(self):
        manager_id, _ = self.add_alert('manager', 0, agent='000')
        mapped_id, _ = self.add_alert('mapped', 0)
        manager = self.context(manager_id)
        mapped = self.context(mapped_id)
        self.assertEqual(manager['reported_system'], 'Wazuh Manager (agent 000)')
        self.assertIsNone(manager['asset_name'])
        self.assertIsNone(manager['criticality'])
        self.assertEqual(mapped['asset_name'], 'lab')
        self.assertEqual(mapped['criticality'], 'critical')
        client = self.client()
        page = client.get(f'/alerts/groups/{manager_id}').data.decode()
        self.assertIn('Wazuh Manager (agent 000)', page)
        self.assertIn('Not mapped', page)
        self.assertEqual(client.get('/alerts/groups/999999').status_code, 404)

    def test_mitre_union_history_and_latest_case_pivot(self):
        first_id, first_case = self.add_alert('mitre-one', 0, mitre=['T1110'])
        last_id, last_case = self.add_alert('mitre-two', 1, mitre=['T1059.001'])
        group = self.context(last_id)
        self.assertEqual(group['mitre_ids'], ['T1110', 'T1059.001'])
        self.assertEqual(group['representative_alert_id'], last_id)
        self.assertEqual(group['representative_incident_id'], last_case)
        self.assertEqual(group['alert_ids'], [first_id, last_id])
        self.assertIn(first_case, group['incident_ids'])
        html = self.client().get(f'/alerts/groups/{last_id}').data.decode()
        self.assertIn('T1110', html)
        self.assertIn('T1059.001', html)
        self.assertIn(f'/alerts/groups/{last_id}/investigate', html)
        self.assertIn('Occurrence History (2)', html)
        self.assertIn('mitre-one', html)
        self.assertIn('mitre-two', html)

    def test_search_keeps_whole_group_and_pagination_counts_groups(self):
        ids = [self.add_alert(f'search-{n}', n)[0] for n in range(3)]
        self.add_alert('unrelated', 0, agent='002')
        with app.app_context():
            groups, pagination = list_alerts(self.db, {'q': 'search-1'})
        self.assertEqual(pagination['total'], 1)
        self.assertEqual(pagination['raw_total'], 3)
        self.assertEqual(groups[0]['alert_ids'], ids)
        html = self.client().get('/alerts?q=search-1').data.decode()
        self.assertIn('3 occurrences', html)
        self.assertNotIn('unrelated', html)

    def test_firedtimes_is_not_an_occurrence_count_and_bad_raw_is_safe(self):
        first, _ = self.add_alert('firedtimes-one', 0, firedtimes=900)
        self.assertEqual(self.context(first)['occurrences'], 1)
        second, _ = self.add_alert('firedtimes-two', 1, firedtimes=901)
        self.assertEqual(self.context(first)['occurrences'], 2)
        with self.db:
            self.db.execute('UPDATE alerts SET raw_alert=? WHERE id=?',
                            ('legacy non-JSON record', second))
        self.assertEqual(self.context(first)['alert_ids'], [first, second])

    def test_group_pagination_limits_browser_rows(self):
        for number in range(21):
            self.add_alert(f'page-{number}', 0, rule=str(60000 + number))
        with app.app_context():
            first_page, first = list_alerts(self.db, {'page': '1'})
            last_page, last = list_alerts(self.db, {'page': '2'})
        self.assertEqual((first['total'], first['pages'], len(first_page)), (21, 2, 20))
        self.assertEqual((last['total'], last['pages'], len(last_page)), (21, 2, 1))

    def test_authentication_and_read_only_group_queries(self):
        alert_id, _ = self.add_alert('read-only-alert', 0)
        self.assertEqual(app.test_client().get('/alerts/groups/' + str(alert_id)).status_code, 302)
        before = self.db.total_changes
        readonly = sqlite3.connect(f'file:{self.db.execute("PRAGMA database_list").fetchone()[2]}?mode=ro',
                                   uri=True)
        readonly.row_factory = sqlite3.Row
        try:
            with app.app_context():
                groups, _ = list_alerts(readonly, {})
                detail = group_context(readonly, alert_id)
            self.assertEqual(groups[0]['occurrences'], 1)
            self.assertEqual(detail['alert_ids'], [alert_id])
        finally:
            readonly.close()
        self.assertEqual(self.db.total_changes, before)

    def test_grouped_row_title_opens_review_without_starting_investigation(self):
        first_id, _ = self.add_alert('review-first', 0, mitre=['T1110'])
        last_id, case_id = self.add_alert('review-last', 1, mitre=['T1110'])
        client = self.client()
        counts_before = tuple(self.db.execute('''
            SELECT (SELECT COUNT(*) FROM investigations),
                   (SELECT COUNT(*) FROM investigation_findings),
                   (SELECT COUNT(*) FROM risk_assessments)
        ''').fetchone())

        queue = client.get('/alerts')
        self.assertEqual(queue.status_code, 200)
        self.assertIn(
            f'href="/alerts/groups/{last_id}"',
            queue.data.decode(),
        )
        self.assertIn('Review detection', queue.data.decode())
        self.assertNotIn('Investigate group →', queue.data.decode())

        detail = client.get(f'/alerts/groups/{last_id}')
        self.assertEqual(detail.status_code, 200)
        html = detail.data.decode()
        for label in ('Alert Summary', 'Wazuh Detection Level', 'T1110',
                      'Investigation status', 'Reported Wazuh Source',
                      'Agent Name', 'Agent ID', 'Configured CDSS Asset',
                      'Administrator-defined criticality', 'Contextual assessment scope',
                      'Occurrence Summary', 'First Seen', 'Last Seen'):
            self.assertIn(label, html)
        self.assertIn('WIN-001', html)
        self.assertIn('lab', html)
        self.assertIn('<details>', html)
        self.assertIn('<summary>Occurrence History (2)</summary>', html)
        self.assertNotIn('<details open', html)
        self.assertIn(f'href="/alerts/{first_id}"', html)
        self.assertIn(f'href="/alerts/{last_id}"', html)
        self.assertIn(f'/alerts/groups/{last_id}/investigate', html)
        self.assertIn('>Investigate</button>', html)
        self.assertEqual(client.get(f'/incidents/{case_id}').status_code, 200)

        counts_after = tuple(self.db.execute('''
            SELECT (SELECT COUNT(*) FROM investigations),
                   (SELECT COUNT(*) FROM investigation_findings),
                   (SELECT COUNT(*) FROM risk_assessments)
        ''').fetchone())
        self.assertEqual(counts_after, counts_before)

    def test_explicit_investigate_creates_once_then_opens_existing_case(self):
        alert_id, _ = self.add_alert('explicit-only', 0)
        client = self.client()
        before = self.db.execute('SELECT COUNT(*) FROM investigation_case_alerts').fetchone()[0]
        self.assertIn('>Investigate</button>', client.get(f'/alerts/groups/{alert_id}').data.decode())
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigation_case_alerts').fetchone()[0], before)
        response = client.post(f'/alerts/groups/{alert_id}/investigate',
                               data={'csrf_token':'test-token'})
        self.assertEqual(response.status_code, 302)
        case_id = self.db.execute('SELECT case_id FROM investigation_case_alerts WHERE alert_id=?',
                                  (alert_id,)).fetchone()[0]
        self.assertIn(f'/incidents/{case_id}', response.headers['Location'])
        detail = client.get(f'/alerts/groups/{alert_id}').data.decode()
        self.assertIn('Open Investigation', detail)
        self.assertNotIn('>Investigate</button>', detail)
        runs = self.db.execute('SELECT COUNT(*) FROM investigations WHERE incident_id=?',
                               (case_id,)).fetchone()[0]
        repeated = client.post(f'/alerts/groups/{alert_id}/investigate',
                               data={'csrf_token':'test-token'})
        self.assertIn(f'/incidents/{case_id}', repeated.headers['Location'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM investigations WHERE incident_id=?',
                                         (case_id,)).fetchone()[0], runs)

    def test_failed_archive_rerun_preserves_previous_assessment(self):
        alert_id, _ = self.add_alert('archive-rerun', 0)
        client = self.client()
        client.post(f'/alerts/groups/{alert_id}/investigate',data={'csrf_token':'test-token'})
        case_id = self.db.execute('SELECT case_id FROM investigation_case_alerts WHERE alert_id=?',
                                  (alert_id,)).fetchone()[0]
        assessed = self.db.execute("SELECT id,assessed_at FROM risk_assessments WHERE incident_id=? AND assessment_stage='contextual' ORDER BY id DESC LIMIT 1",
                                   (case_id,)).fetchone()
        self.assertIsNotNone(assessed)
        run_count = self.db.execute("SELECT COUNT(*) FROM investigations WHERE incident_id=? AND playbook_key<>'wazuh_archive_retrieval_v1'",
                                    (case_id,)).fetchone()[0]
        response = client.post(f'/incidents/{case_id}/investigations',
                               data={'csrf_token':'test-token'},follow_redirects=True)
        self.assertIn(b'Latest evidence retrieval unavailable',response.data)
        self.assertIn(b'Last successful assessment:',response.data)
        self.assertIn(assessed['assessed_at'].encode(),response.data)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM investigations WHERE incident_id=? AND playbook_key<>'wazuh_archive_retrieval_v1'",
                                         (case_id,)).fetchone()[0],run_count)
        self.assertEqual(self.db.execute("SELECT id FROM risk_assessments WHERE incident_id=? AND assessment_stage='contextual' ORDER BY id DESC LIMIT 1",
                                         (case_id,)).fetchone()[0],assessed['id'])


if __name__ == '__main__':
    unittest.main()
