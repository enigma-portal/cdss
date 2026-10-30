"""Connection administration must preserve collection and immutable-source truth."""
import json
import socket
import sqlite3
import unittest
from contextlib import closing
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import test_phase2_ingestion as fixtures
import test_auth as auth_fixtures
from app.database import get_db_connection
from app.services.poller import _poll_once
from app.services.wazuh_indexer import WazuhIndexerClient
from run import app


class ConnectorIntegrationTests(unittest.TestCase):
    add_connector = fixtures.PhaseTwoIngestionTests.add_connector
    _csrf = auth_fixtures.AuthenticationTests._csrf
    _create_admin = auth_fixtures.AuthenticationTests._create_admin

    def setUp(self):
        fixtures.PhaseTwoIngestionTests.setUp(self)
        self.client = app.test_client()
        self.polling_setting = app.config.get('SIEM_REALTIME_ENABLED')
        app.config['SIEM_REALTIME_ENABLED'] = True
        self.key_patch = patch('app.services.secret_store.KEY_FILE', Path(self.directory.name)/'test.key')
        self.key_patch.start()
        self._create_admin()

    def tearDown(self):
        self.key_patch.stop()
        app.config['SIEM_REALTIME_ENABLED'] = self.polling_setting
        fixtures.PhaseTwoIngestionTests.tearDown(self)

    def poll(self, hits=(), error=None, on_fetch=None):
        client = WazuhIndexerClient('https://siem.example', 'reader', 'fixture-only')
        transport = SimpleNamespace(fetch_event_page=client.fetch_alert_page)
        response = {'timed_out':False, '_shards':{'failed':0}, 'hits':{'hits':list(hits)}}
        def fetch(*args, **kwargs):
            on_fetch()
            return response
        with patch.object(client, '_request_json', return_value=response, side_effect=fetch if on_fetch else error), \
             patch('app.services.poller.create_connector', return_value=transport), \
             patch('app.services.poller.unprotect_secret', return_value='fixture-only'):
            _poll_once(100, 0)

    def hit(self, suffix, payload=None):
        return {'_index':'wazuh-alerts-test', '_id':'doc'+str(suffix), 'sort':[1000+suffix,'doc'+str(suffix)],
                '_source':payload if payload is not None else fixtures.event('source-'+str(suffix))}

    def connection_test(self, cid):
        transport = SimpleNamespace(test_connection=lambda: {'status':'green'})
        address = [(socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.10.10.10',9200))]
        with patch('socket.getaddrinfo', return_value=address), \
             patch('app.routes.auth.create_connector', return_value=transport), \
             patch('app.routes.auth.unprotect_secret', return_value='fixture-only'):
            return self.client.post(f'/admin/siem-connections/{cid}/test', data={'csrf_token':self._csrf()})

    def test_connection_test_alone_never_proves_collection(self):
        cid = self.add_connector()
        self.assertEqual(self.connection_test(cid).status_code,302)
        html = self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertNotIn('SIEM alert collection active', html)
        self.assertIn('SIEM alert collection status unknown', html)
        with closing(get_db_connection()) as db:
            row = db.execute('SELECT * FROM siem_connections').fetchone()
            self.assertEqual(row['status'],'connected')
            self.assertIsNotNone(row['response_time_ms'])
            self.assertEqual(row['cluster_health'],'green')
            self.assertIsNone(row['last_poll_success_at'])

    def test_connection_test_cannot_hide_durable_rejections(self):
        cid = self.add_connector()
        self.poll([self.hit(1, {'id':'bad','rule':{}})])
        self.assertEqual(self.connection_test(cid).status_code,302)
        html = self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertIn('source documents need review',html)
        self.assertNotIn('SIEM alert collection active',html)

    def test_zero_alert_poll_is_active_and_manual_test_cannot_hide_poll_failure(self):
        cid = self.add_connector()
        self.poll()
        html = self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertIn('SIEM alert collection active',html)
        self.poll(error=RuntimeError('fixture failure'))
        self.connection_test(cid)
        html = self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertIn('alert collection interrupted',html)
        self.assertNotIn('SIEM alert collection active',html)

    def test_recreated_logical_source_replays_without_false_collision_or_rewrite(self):
        first = self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db:
            original = tuple(db.execute('SELECT * FROM alerts').fetchone())
            with db: db.execute('UPDATE siem_connections SET is_enabled=0 WHERE id=?',(first,))
        deleted = self.client.post(f'/admin/siem-connections/{first}/delete',
            data={'csrf_token':self._csrf(),'confirm_name':'test'})
        self.assertEqual(deleted.status_code,302)
        created = self.client.post('/admin/siem-connections',data={
            'csrf_token':self._csrf(),'name':'Replacement','connector_type':'wazuh_indexer',
            'base_url':'https://SIEM.Example.','port':'9200','index_pattern':'wazuh-alerts-*',
            'username':'new-reader','password':'DisposableTestingOnly','verify_tls':'1'})
        self.assertEqual(created.status_code,302)
        with closing(get_db_connection()) as db, db:
            second = db.execute('SELECT id FROM siem_connections').fetchone()[0]
            db.execute('UPDATE siem_connections SET is_enabled=1')
        self.assertNotEqual(first,second)
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
            self.assertEqual(tuple(db.execute('SELECT * FROM alerts').fetchone()),original)
            observed = db.execute('SELECT connection_id FROM alert_source_documents ORDER BY connection_id').fetchall()
            self.assertEqual([r[0] for r in observed],[first,second])
        self.poll([self.hit(2)])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],2)
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_different_endpoint_cannot_claim_an_existing_document(self):
        cid = self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db, db:
            db.execute('UPDATE siem_connections SET base_url=? WHERE id=?',('https://other.example',cid))
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],1)

    def test_settings_edit_invalidates_poll_proof_even_after_manual_test(self):
        cid = self.add_connector()
        self.poll()
        response = self.client.post(f'/admin/siem-connections/{cid}/edit',data={
            'csrf_token':self._csrf(),'name':'Edited source','base_url':'https://other.example',
            'port':'9200','index_pattern':'wazuh-alerts-*','username':'reader','verify_tls':'1'})
        self.assertEqual(response.status_code,302)
        self.connection_test(cid)
        with closing(get_db_connection()) as db, db:
            db.execute('UPDATE siem_connections SET is_enabled=1')
        html = self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertNotIn('SIEM alert collection active',html)

    def test_unknown_historical_provenance_is_not_guessed_from_current_endpoint(self):
        self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db, db:
            db.execute('UPDATE alert_source_documents SET source_namespace=NULL')
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],1)
            self.assertIsNone(db.execute('SELECT source_namespace FROM alert_source_documents').fetchone()[0])

    def test_recreated_source_retains_prior_quarantine_visibility(self):
        first = self.add_connector()
        self.poll([self.hit(1,{'id':'bad','rule':{}})])
        with closing(get_db_connection()) as db, db:
            db.execute('DELETE FROM siem_connections WHERE id=?',(first,))
        second = self.add_connector()
        self.poll()
        self.connection_test(second)
        html = self.client.get('/admin/siem-connections').get_data(as_text=True)
        self.assertIn('source documents need review',html)
        self.assertNotIn('SIEM alert collection active',html)

    def test_manual_failure_does_not_rewrite_collection_proof_or_cursor(self):
        cid = self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db:
            before = tuple(db.execute('SELECT poll_status,last_poll_success_at,last_poll_error FROM siem_connections').fetchone())
            cursor = tuple(db.execute('SELECT * FROM ingestion_cursors').fetchone())
        with patch('socket.getaddrinfo', side_effect=socket.gaierror('fixture-only')):
            self.client.post(f'/admin/siem-connections/{cid}/test',data={'csrf_token':self._csrf()})
        with closing(get_db_connection()) as db:
            self.assertEqual(tuple(db.execute('SELECT poll_status,last_poll_success_at,last_poll_error FROM siem_connections').fetchone()),before)
            self.assertEqual(tuple(db.execute('SELECT * FROM ingestion_cursors').fetchone()),cursor)
        self.assertIn('SIEM alert collection active',self.client.get('/admin/siem-connections').get_data(as_text=True))

    def test_rejections_have_bounded_specific_reasons(self):
        self.add_connector()
        self.poll([self.hit(1,{'id':'bad','rule':{}})])
        self.poll([self.hit(2)])
        self.poll([self.hit(2,fixtures.event('changed-id'))])
        self.poll([self.hit(3,fixtures.event('source-2','002'))])
        with closing(get_db_connection()) as db:
            reasons = [r[0] for r in db.execute('SELECT reason FROM rejected_source_events ORDER BY id')]
            self.assertEqual(reasons,['malformed_event','changed_document','source_identity_conflict'])

    def test_rejected_identity_cannot_be_silently_reused_by_another_endpoint(self):
        cid = self.add_connector()
        malformed = self.hit(1,{'id':'bad','rule':{}})
        self.poll([malformed])
        with closing(get_db_connection()) as db, db:
            db.execute('UPDATE siem_connections SET base_url=? WHERE id=?',('https://other.example',cid))
        self.poll([self.hit(2),malformed])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT document_id FROM ingestion_cursors').fetchone()[0],'doc1')
            self.assertEqual(db.execute('SELECT poll_status FROM siem_connections').fetchone()[0],'error')

    def test_recreation_does_not_allow_changed_logical_document_with_new_alert_id(self):
        first = self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db, db:
            db.execute('DELETE FROM siem_connections WHERE id=?',(first,))
        self.add_connector()
        self.poll([self.hit(1,fixtures.event('changed-id'))])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
            self.assertEqual(db.execute('SELECT reason FROM rejected_source_events').fetchone()[0],'changed_document')

    def test_edit_during_fetch_cannot_mint_provenance_or_poll_proof_for_new_source(self):
        self.add_connector()
        for payload,endpoint in ((None,'https://second.example'),({'id':'bad','rule':{}},'https://third.example')):
            def edit():
                with closing(get_db_connection()) as db, db:
                    db.execute('UPDATE siem_connections SET base_url=?',(endpoint,))
            self.poll([self.hit(1,payload)],on_fetch=edit)
            with closing(get_db_connection()) as db:
                self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM alert_source_documents').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT COUNT(*) FROM ingestion_cursors').fetchone()[0],0)
                self.assertEqual(db.execute('SELECT poll_status,last_poll_success_at FROM siem_connections').fetchone()[:],('not_tested',None))

    def test_absent_historical_provenance_does_not_acquire_an_invented_origin(self):
        self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db, db:
            db.execute('DELETE FROM alert_source_documents')
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alert_source_documents').fetchone()[0],0)
            self.assertEqual(db.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],1)

    def test_logical_identity_lookup_has_bounded_work_at_history_volume(self):
        cid = self.add_connector()
        self.poll([self.hit(1)])
        with closing(get_db_connection()) as db, db:
            alert_id = db.execute('SELECT id FROM alerts').fetchone()[0]
            db.executemany('''INSERT INTO alert_source_documents
                (connection_id,source_index,source_document_id,alert_id,source_namespace) VALUES(?,?,?,?,?)''',
                ((cid,'history','old-'+str(i),alert_id,'other-source') for i in range(20000)))
        ticks = []
        def bounded_connection():
            db = get_db_connection()
            def progress():
                ticks.append(1)
                return int(len(ticks)>20)
            db.set_progress_handler(progress,1000)
            return db
        with patch('app.services.incident_processor.get_db_connection',side_effect=bounded_connection):
            self.poll([self.hit(2)])
        with closing(get_db_connection()) as db:
            self.assertEqual(db.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],2,
                             'New logical-document lookup must complete within 20,000 SQLite operations')


class MigrationAndNamespaceTests(unittest.TestCase):
    def test_additive_migration_does_not_invent_poll_or_historical_namespace(self):
        from app.database.ingestion_safety import migrate_ingestion_safety
        with closing(sqlite3.connect(':memory:')) as db:
            db.execute('CREATE TABLE siem_connections(id INTEGER PRIMARY KEY,status TEXT,last_success_at TEXT)')
            db.execute("INSERT INTO siem_connections VALUES(1,'connected','2026-10-30T10:00:00Z')")
            db.execute('''CREATE TABLE alert_source_documents(connection_id INTEGER,source_index TEXT,
                source_document_id TEXT,alert_id INTEGER,PRIMARY KEY(connection_id,source_index,source_document_id))''')
            db.execute("INSERT INTO alert_source_documents VALUES(1,'alerts','doc',10)")
            migrate_ingestion_safety(db)
            migrate_ingestion_safety(db)
            self.assertEqual(db.execute('SELECT status,last_success_at FROM siem_connections').fetchone(),
                             ('connected','2026-10-30T10:00:00Z'))
            self.assertEqual(db.execute('SELECT poll_status,last_poll_success_at FROM siem_connections').fetchone(),('not_tested',None))
            self.assertEqual(db.execute('SELECT source_namespace FROM alert_source_documents').fetchone(),(None,))

    def test_logical_namespace_normalizes_origin_without_dns_or_credentials(self):
        from app.services.ingestion_safety import source_namespace
        with patch('socket.getaddrinfo', side_effect=AssertionError('Identity cannot resolve DNS')):
            for url in ('https://SIEM.Example./','https://siem.example:9200'):
                row={'connector_type':'wazuh_indexer','base_url':url,'port':9200}
                self.assertEqual(source_namespace(row),'["endpoint-v1","wazuh_indexer","siem.example",9200]')
            row={'connector_type':'wazuh_indexer','base_url':'https://[2001:db8:0:0::1]','port':443}
            self.assertEqual(source_namespace(row),'["endpoint-v1","wazuh_indexer","2001:db8::1",443]')
