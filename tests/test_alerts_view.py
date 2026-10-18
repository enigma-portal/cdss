"""Analyst alert queue and source/asset presentation, without methodology changes."""

import unittest

import test_contextual_risk as fixtures
from run import app
from app.services.contextual_risk import assess_investigation
from app.services.investigation import run_investigation
from app.services.incident_processor import process_alert


class AlertsViewTests(unittest.TestCase):
    setUp = fixtures.ContextualRiskTests.setUp
    tearDown = fixtures.ContextualRiskTests.tearDown
    client = fixtures.ContextualRiskTests.client

    def source_alert(self, name, agent_id, agent_name, agent_ip=None, mitre=None, groups=None):
        source = {
            'id': name, 'timestamp': '2026-10-09T06:11:25.001+0000',
            'rule': {'id': '5710', 'description': 'Authentication failure observed',
                     'level': 7, 'groups': groups if groups is not None else ['authentication_failed']},
            'agent': {'id': agent_id, 'name': agent_name},
            'data': {'srcip': '192.0.2.40', 'password': 'RAW-ONLY-SECRET'},
        }
        if agent_ip is not None:
            source['agent']['ip'] = agent_ip
        if mitre:
            source['rule']['mitre'] = {'id': mitre}
        case_id = process_alert(source)['incident_id']
        alert_id = self.db.execute(
            'SELECT id FROM alerts WHERE wazuh_alert_id=?', (name,)
        ).fetchone()[0]
        return alert_id, case_id

    def test_alerts_require_authentication_and_have_detail_route(self):
        alert_id, _ = self.source_alert('auth-1', '000', 'wazuh')
        self.assertEqual(app.test_client().get('/alerts').status_code, 302)
        self.assertEqual(app.test_client().get(f'/alerts/{alert_id}').status_code, 302)
        client = self.client()
        self.assertEqual(client.get('/alerts').status_code, 200)
        self.assertEqual(client.get(f'/alerts/{alert_id}').status_code, 200)
        self.assertEqual(client.get('/alerts/999999').status_code, 404)

    def test_unmapped_manager_source_visible_without_invented_asset(self):
        alert_id, case_id = self.source_alert('manager-alert', '000', 'wazuh')
        client = self.client()
        queue = client.get('/alerts').data.decode()
        detail = client.get(f'/alerts/{alert_id}').data.decode()
        case = client.get(f'/incidents/{case_id}').data.decode()
        for page in (queue, detail, case):
            self.assertIn('Wazuh Manager (agent 000)', page)
            self.assertIn('wazuh', page)
            self.assertIn('Not mapped', page)
        self.assertIn('Monitored Endpoint IP: Not provided', queue)
        self.assertIn('Monitored Endpoint IP</dt><dd>Not provided', detail)
        self.assertIn('Agent ID</dt><dd>000', detail)
        self.assertIn('CDSS Assessment: Pending Investigation', queue)
        self.assertIn('Pending Investigation', case)
        self.assertNotIn('RAW-ONLY-SECRET', queue)
        self.assertNotIn('RAW-ONLY-SECRET', detail)
        self.assertNotIn('Criticality: Critical', queue)
        self.assertIsNone(self.db.execute(
            'SELECT asset_id FROM alerts WHERE id=?', (alert_id,)
        ).fetchone()[0])

    def test_mapped_source_and_asset_are_separate_with_mitre_ids(self):
        alert_id, case_id = self.source_alert(
            'mapped-alert', '001', 'DESKTOP-TEST', '172.16.16.40', ['T1110', 'T1059.001']
        )
        client = self.client()
        for path in ('/alerts', f'/alerts/{alert_id}', f'/incidents/{case_id}'):
            html = client.get(path).data.decode()
            self.assertIn('DESKTOP-TEST', html)
            self.assertIn('lab', html)
            self.assertIn('172.16.16.40', html)
            self.assertIn('Wazuh Detection Level', html)
            self.assertIn('T1110', html)
            self.assertIn('T1059.001', html)
        detail = client.get(f'/alerts/{alert_id}').data.decode()
        self.assertLess(detail.index('Reported Wazuh Source'), detail.index('Configured CDSS Asset'))
        self.assertIn('Agent ID</dt><dd>001', detail)
        self.assertIn('Administrator-defined criticality', detail)
        self.assertIn('Review Grouped Alert', detail)
        self.assertNotIn('RAW-ONLY-SECRET', detail)

    def test_status_progression_uses_existing_saved_records(self):
        alert_id, case_id = self.source_alert('status-alert', '001', 'DESKTOP-TEST')
        client = self.client()
        path = f'/alerts/{alert_id}'
        self.assertIn(b'Current status: <strong>New</strong>', client.get(path).data)
        investigation_id = run_investigation(case_id)
        self.assertIn(b'Investigation Started', client.get(path).data)
        assess_investigation(case_id, investigation_id)
        self.assertIn(b'Current status: <strong>Assessed</strong>', client.get(path).data)
        manager_id, manager_case = self.source_alert(
            'fallback-alert', '000', 'wazuh', groups=['windows']
        )
        assess_investigation(manager_case, run_investigation(manager_case))
        self.assertIn(b'Current status: <strong>Inconclusive</strong>',
                      client.get(f'/alerts/{manager_id}').data)

    def test_search_and_escaping_do_not_expose_raw_json(self):
        alert_id, _ = self.source_alert('source-escape', '999', '<script>source()</script>')
        client = self.client()
        html = client.get('/alerts?q=source-escape').data.decode()
        self.assertIn('source-escape', html)
        self.assertIn('&lt;script&gt;source()', html)
        self.assertNotIn('<script>source()</script>', html)
        self.assertNotIn('RAW-ONLY-SECRET', html)
        self.assertNotIn('raw_alert', html)
        self.assertNotIn('<pre', html)
        self.assertNotIn('mapped-alert', html)
        self.assertEqual(client.get('/alerts?page=invalid').status_code, 200)
        self.assertEqual(client.get(f'/alerts/{alert_id}').status_code, 200)
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(), [])


if __name__ == '__main__':
    unittest.main()
