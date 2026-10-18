"""Phase 4 conservative membership, migration, and legacy isolation tests."""
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import app.database as database
from app.database.seed import seed_knowledge_base
from app.database.phase4 import migrate_incident_alerts
from app.services.incident_processor import process_alert
from app.services.asset_resolver import backfill_asset_links


class IncidentCorrelationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.original = database.DATABASE
        database.DATABASE = Path(self.temp.name) / 'phase4.db'
        seed_knowledge_base()
        self.db = database.get_db_connection()
        with self.db:
            for agent, protected in [('001',1),('002',1),('003',0)]:
                self.db.execute('''INSERT INTO assets(asset_name,asset_type,asset_role,os_family,
                    os_name,wazuh_agent_id,criticality,is_protected,ip_address)
                    VALUES('server','Server','Other','Other','Other',?,'high',?,'10.0.0.1')''',
                    (agent, protected))

    def tearDown(self):
        self.db.close()
        database.DATABASE = self.original
        self.temp.cleanup()

    def event(self, identifier, minute=0, agent='001', source=None, user=None,
              destination=None, path=None, mitre=None, firedtimes=1):
        value = {'id':identifier,'timestamp':(datetime(2026,9,26,12,tzinfo=timezone.utc)+timedelta(minutes=minute)).isoformat(),
                 'agent':{'id':agent,'ip':'10.0.0.1'},
                 'rule':{'id':'rule-'+identifier,'level':8,'description':'Security event',
                         'firedtimes':firedtimes}, 'data':{}}
        for key,item in [('srcip',source),('dstip',destination),('srcuser',user)]:
            if item is not None:
                value['data'][key]=item
        if path:
            value['syscheck']={'path':path}
        if mitre:
            value['rule']['mitre']={'id':mitre}
        return value

    def clear(self):
        with self.db:
            self.db.execute('DELETE FROM incidents')
            self.db.execute('DELETE FROM alerts')

    def scores_and_guidance(self):
        return {table:[tuple(r) for r in self.db.execute('SELECT * FROM '+table+' ORDER BY id')]
                for table in ('risk_scores','incident_recommendations')}

    def test_supported_entities_and_explainable_reasons(self):
        for fields,reason in [({'source':'192.0.2.5'},'same_asset_and_source_ip'),
                              ({'user':'alice'},'same_asset_and_username'),
                              ({'destination':'192.0.2.8'},'same_asset_and_destination_ip'),
                              ({'source':'192.0.2.5','user':'alice'},'same_asset_source_ip_and_username'),
                              ({'path':'/etc/example'},'same_asset_and_syscheck_path')]:
            with self.subTest(fields=fields):
                self.clear()
                first=process_alert(self.event('a',**fields))
                before=self.scores_and_guidance()
                second_event=self.event('b',minute=10,**fields)
                second=process_alert(second_event)
                self.assertEqual(first['incident_id'],second['incident_id'])
                self.assertEqual(second['correlation_reason'],reason)
                self.assertEqual(before,self.scores_and_guidance())
                self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incident_alerts').fetchone()[0],2)
                row=self.db.execute("SELECT processing_status,raw_alert FROM alerts WHERE wazuh_alert_id='b'").fetchone()
                self.assertEqual(row[0],'processed')
                self.assertEqual(json.loads(row[1]),second_event)

    def test_asset_only_rule_mitre_and_firedtimes_do_not_correlate(self):
        first=self.event('a',mitre=['T1110'],firedtimes=500)
        second=self.event('b',mitre=['T1110'],firedtimes=9999)
        second['rule']['id']=first['rule']['id']
        a=process_alert(first); b=process_alert(second)
        self.assertNotEqual(a['incident_id'],b['incident_id'])

    def test_different_assets_do_not_correlate_source_or_username(self):
        for fields in ({'source':'192.0.2.5'},{'user':'alice'}):
            self.clear()
            a=process_alert(self.event('a',**fields))
            b=process_alert(self.event('b',agent='002',**fields))
            self.assertNotEqual(a['incident_id'],b['incident_id'])

    def test_null_and_unprotected_assets_do_not_correlate(self):
        for agent in ('unknown','003'):
            self.clear()
            a=process_alert(self.event('a',agent=agent,source='192.0.2.5'))
            b=process_alert(self.event('b',agent=agent,source='192.0.2.5'))
            self.assertNotEqual(a['incident_id'],b['incident_id'])

    def test_window_boundary_config_and_timezone_equivalence(self):
        a=process_alert(self.event('a',source='192.0.2.5'))
        b=process_alert(self.event('b',minute=15,source='192.0.2.5'))
        self.assertEqual(a['incident_id'],b['incident_id'])
        c=process_alert(self.event('c',minute=31,source='192.0.2.5'))
        self.assertNotEqual(a['incident_id'],c['incident_id'])
        self.clear()
        with self.db:
            self.db.execute("UPDATE system_settings SET setting_value='2' WHERE setting_key='incident_correlation_window_minutes'")
        a=process_alert(self.event('a',source='192.0.2.5'))
        b=process_alert(self.event('b',minute=3,source='192.0.2.5'))
        self.assertNotEqual(a['incident_id'],b['incident_id'])
        equivalent=self.event('d',source='192.0.2.5')
        equivalent['timestamp']='2026-09-26T17:00:00+05:00'
        d=process_alert(equivalent)
        self.assertEqual(a['incident_id'],d['incident_id'])

    def test_finalized_incidents_and_investigating_state(self):
        for status in ('closed','contained','investigating'):
            self.clear()
            a=process_alert(self.event('a',user='alice'))
            with self.db:
                self.db.execute('UPDATE incidents SET status=?',(status,))
            b=process_alert(self.event('b',user='alice'))
            self.assertEqual(a['incident_id']==b['incident_id'],status=='investigating')

    def test_most_recent_qualifying_incident_selected(self):
        a=process_alert(self.event('a',source='192.0.2.1',user='alice'))
        b=process_alert(self.event('b',minute=2,source='192.0.2.2',user='bob'))
        self.assertNotEqual(a['incident_id'],b['incident_id'])
        bridge=process_alert(self.event('c',minute=3,source='192.0.2.1',user='bob'))
        self.assertEqual(bridge['incident_id'],b['incident_id'])

    def test_destination_equal_to_asset_is_not_extra_context(self):
        a=process_alert(self.event('a',destination='10.0.0.1'))
        b=process_alert(self.event('b',destination='10.0.0.1'))
        self.assertNotEqual(a['incident_id'],b['incident_id'])

    def test_membership_unique_and_duplicate_correlated_alert_safe(self):
        a=process_alert(self.event('a',user='alice'))
        event=self.event('b',user='alice')
        process_alert(event)
        repeated=process_alert(event)
        self.assertEqual(repeated['incident_id'],a['incident_id'])
        self.assertFalse(repeated['created'])
        with self.assertRaises(sqlite3.IntegrityError),self.db:
            self.db.execute("INSERT INTO incident_alerts SELECT incident_id,alert_id,'duplicate',9,added_at FROM incident_alerts LIMIT 1")
        other=process_alert(self.event('unrelated'))
        with self.assertRaises(sqlite3.IntegrityError),self.db:
            self.db.execute("INSERT INTO incident_alerts(incident_id,alert_id,correlation_reason,ordinal) VALUES(?,1,'invalid',9)",(other['incident_id'],))

    def test_mitre_union_and_provenance_without_risk_update(self):
        first=process_alert(self.event('a',user='alice',mitre=['T1110']))
        before=self.scores_and_guidance()
        process_alert(self.event('b',user='alice',mitre=['T1110','T1059.001']))
        ids=[r[0] for r in self.db.execute('SELECT technique_id FROM incident_mitre_techniques WHERE incident_id=? ORDER BY ordinal',(first['incident_id'],))]
        self.assertEqual(ids,['T1110','T1059.001'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incident_mitre_sources').fetchone()[0],3)
        self.assertEqual(before,self.scores_and_guidance())

    def test_170_legacy_seeds_migrate_without_merges(self):
        with self.db:
            for n in range(170):
                aid=self.db.execute("INSERT INTO alerts(wazuh_alert_id,event_timestamp,rule_id,raw_alert) VALUES(?,'2026-09-01T00:00:00Z','legacy','{}')",(str(n),)).lastrowid
                self.db.execute("INSERT INTO incidents(alert_id,title,detected_at) VALUES(?,'legacy','2026-09-01T00:00:00Z')",(aid,))
            snapshot=[tuple(r) for r in self.db.execute('SELECT id,alert_id,title,detected_at FROM incidents')]
            migrate_incident_alerts(self.db)
            migrate_incident_alerts(self.db)
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incident_alerts').fetchone()[0],170)
        self.assertEqual(self.db.execute("SELECT COUNT(*) FROM incident_alerts WHERE correlation_reason='seed_migrated'").fetchone()[0],170)
        self.assertEqual(snapshot,[tuple(r) for r in self.db.execute('SELECT id,alert_id,title,detected_at FROM incidents')])
        self.assertEqual(self.db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_failed_correlation_rolls_back_and_retry_succeeds(self):
        first=process_alert(self.event('a',user='alice'))
        with patch('app.services.incident_processor.attach_alert_context',side_effect=RuntimeError('test')):
            with self.assertRaises(RuntimeError):
                process_alert(self.event('b',user='alice'))
        self.assertEqual(self.db.execute("SELECT processing_status FROM alerts WHERE wazuh_alert_id='b'").fetchone()[0],'failed')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incident_alerts').fetchone()[0],1)
        self.assertEqual(process_alert(self.event('b',user='alice'))['incident_id'],first['incident_id'])

    def test_concurrent_related_alerts_form_one_incident(self):
        with ThreadPoolExecutor(max_workers=2) as pool:
            results=list(pool.map(process_alert,[self.event('a',user='alice'),self.event('b',user='alice')]))
        self.assertEqual(results[0]['incident_id'],results[1]['incident_id'])
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM incident_alerts').fetchone()[0],2)

    def test_late_event_does_not_regress_last_activity(self):
        first=process_alert(self.event('a',minute=10,user='alice'))
        process_alert(self.event('b',minute=5,user='alice'))
        self.assertEqual(self.db.execute('SELECT last_activity_at FROM incidents WHERE id=?',(first['incident_id'],)).fetchone()[0],'2026-09-26T12:10:00+00:00')

    def test_asset_reassignment_keeps_incident_context_consistent(self):
        process_alert(self.event('a',user='alice'))
        process_alert(self.event('b',user='alice'))
        with self.db:
            asset=self.db.execute("SELECT id FROM assets WHERE wazuh_agent_id='001'").fetchone()[0]
            self.db.execute("UPDATE assets SET wazuh_agent_id=NULL WHERE id=?",(asset,))
            backfill_asset_links(self.db,asset,None)
        self.assertIsNone(self.db.execute('SELECT asset_id FROM incidents').fetchone()[0])
