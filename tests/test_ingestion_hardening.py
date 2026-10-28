"""Real Indexer page handling with disposable transport and SQLite storage."""
import json
import sqlite3
import unittest
from unittest.mock import patch
from types import SimpleNamespace

import test_phase2_ingestion as fixtures
from app.database import get_db_connection
from app.services.poller import _poll_once
from app.services.wazuh_indexer import WazuhIndexerClient


class IngestionHardeningTests(unittest.TestCase):
    def setUp(self):
        fixtures.PhaseTwoIngestionTests.setUp(self)
        self.connections=[]

    def tearDown(self):
        for connection in self.connections:
            connection.close()
        fixtures.PhaseTwoIngestionTests.tearDown(self)

    def connection(self):
        connection=get_db_connection()
        self.connections.append(connection)
        return connection
    add_connector=fixtures.PhaseTwoIngestionTests.add_connector

    def poll(self, hits):
        client=WazuhIndexerClient('https://siem.example','reader','test-only')
        transport=SimpleNamespace(fetch_event_page=client.fetch_alert_page)
        with patch.object(client,'_request_json',return_value={'hits':{'hits':hits}}), \
             patch('app.services.poller.create_connector',return_value=transport), \
             patch('app.services.poller.unprotect_secret',return_value='test-only'):
            _poll_once(100,0)

    def hit(self, name, source=None, index='wazuh-alerts-test'):
        return {'_id':name,'_index':index,'sort':[1000+int(name[-1]),name],
                '_source':source if source is not None else fixtures.event('source-'+name)}

    def test_bad_document_is_durable_and_later_valid_event_survives_restart(self):
        cid=self.add_connector()
        bad={'id':'bad-source','timestamp':'bad','rule':{'id':'1','level':5}}
        # Bootstrap search returns descending order; production reverses it.
        self.poll([self.hit('doc2'), self.hit('doc1',bad)])
        connection=self.connection()
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
        rejected=connection.execute('SELECT * FROM rejected_source_events').fetchone()
        self.assertEqual(json.loads(rejected['raw_event_json']),bad)
        self.assertEqual(rejected['source_document_id'],'doc1')
        self.assertEqual(connection.execute('SELECT document_id FROM ingestion_cursors WHERE connection_id=?',(cid,)).fetchone()[0],'doc2')
        self.poll([self.hit('doc3')])
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],2)
        self.assertEqual(connection.execute('PRAGMA foreign_key_check').fetchall(),[])

    def test_source_id_collision_is_preserved_in_quarantine_not_silently_dropped(self):
        self.add_connector()
        first=fixtures.event('same-source-id')
        second=fixtures.event('same-source-id','002')
        self.poll([self.hit('doc1',first,'source-a')])
        self.poll([self.hit('doc2',second,'source-b')])
        connection=self.connection()
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
        self.assertIsNotNone(connection.execute("SELECT 1 FROM sqlite_master WHERE name='rejected_source_events'").fetchone())
        rejected=connection.execute('SELECT * FROM rejected_source_events').fetchone()
        self.assertIsNotNone(rejected)
        self.assertEqual(json.loads(rejected['raw_event_json']),second)
        self.assertEqual(rejected['source_index'],'source-b')
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alert_source_documents').fetchone()[0],1)

    def test_quarantine_storage_failure_keeps_previous_cursor(self):
        self.add_connector()
        self.poll([self.hit('doc1')])
        connection=self.connection()
        self.assertIsNotNone(connection.execute("SELECT 1 FROM sqlite_master WHERE name='rejected_source_events'").fetchone())
        with connection:
            connection.execute("CREATE TRIGGER reject_quarantine BEFORE INSERT ON rejected_source_events BEGIN SELECT RAISE(ABORT,'offline failure'); END")
        self.poll([self.hit('doc2',{'id':'bad','rule':{}})])
        self.assertEqual(connection.execute('SELECT document_id FROM ingestion_cursors').fetchone()[0],'doc1')

    def test_indexer_retains_identity_without_rewriting_raw_source(self):
        client=WazuhIndexerClient('https://siem.example','reader','test-only')
        hit=self.hit('doc1')
        with patch.object(client,'_request_json',return_value={'hits':{'hits':[hit]}}):
            events,_=client.fetch_alert_page()
        self.assertEqual(dict(events[0]),hit['_source'])
        self.assertEqual(getattr(events[0],'source_index',None),'wazuh-alerts-test')
        self.assertEqual(getattr(events[0],'source_document_id',None),'doc1')

    def test_changed_document_is_not_inserted_as_an_unrelated_second_alert(self):
        self.add_connector()
        self.poll([self.hit('doc1',fixtures.event('first-id'))])
        self.poll([self.hit('doc1',fixtures.event('changed-id'))])
        connection=self.connection()
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],1)

    def test_duplicate_document_and_rejection_replay_are_idempotent(self):
        self.add_connector()
        hits=[self.hit('doc2'),self.hit('doc1',{'id':'bad','rule':{}})]
        self.poll(hits)
        self.poll(hits)
        connection=self.connection()
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM rejected_source_events').fetchone()[0],1)
        self.assertEqual(connection.execute('SELECT status FROM siem_connections').fetchone()[0],'partial')

    def test_identifiable_source_requires_complete_transport_identity(self):
        client=WazuhIndexerClient('https://siem.example','reader','test-only')
        for field in ('_index','_id'):
            hit=self.hit('doc1')
            del hit[field]
            with self.subTest(field=field), patch.object(client,'_request_json',return_value={'hits':{'hits':[hit]}}):
                accepted=True
                try:
                    client.fetch_alert_page()
                except Exception:
                    accepted=False
                self.assertFalse(accepted,'Unidentifiable page must fail before cursor advancement')

    def test_ingestion_migration_failure_rolls_back_caller_transaction(self):
        from app.database.ingestion_safety import migrate_ingestion_safety
        connection=sqlite3.connect(':memory:')
        self.connections.append(connection)
        connection.execute('CREATE TABLE marker(value INTEGER)')
        connection.execute('INSERT INTO marker VALUES(1)')
        connection.set_authorizer(lambda action,a,b,c,d: sqlite3.SQLITE_DENY
            if action==sqlite3.SQLITE_CREATE_INDEX else sqlite3.SQLITE_OK)
        with self.assertRaises(sqlite3.DatabaseError):
            migrate_ingestion_safety(connection)
        connection.set_authorizer(None)
        connection.rollback()
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM marker').fetchone()[0],0)
        self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='alert_source_documents'").fetchone())

    def test_partial_collection_requires_fresh_successful_contact(self):
        from app.services.siem_collection_status import connector_collection_status
        row={'is_enabled':1,'status':'partial','last_success_at':'2026-10-28T09:00:00Z'}
        self.assertEqual(connector_collection_status(row,now='2026-10-28T09:00:10Z').state,'partial')
        self.assertEqual(connector_collection_status(row,now='2026-10-28T10:00:00Z').state,'stale')

    def test_identified_non_object_source_is_preserved_before_valid_document(self):
        self.add_connector()
        malformed=self.hit('doc1')
        malformed['_source']=None
        self.poll([self.hit('doc2'),malformed])
        connection=self.connection()
        self.assertEqual(connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0],1)
        rejected=connection.execute('SELECT raw_event_json FROM rejected_source_events').fetchone()
        self.assertEqual(json.loads(rejected[0]),None)
        self.assertEqual(connection.execute('SELECT document_id FROM ingestion_cursors').fetchone()[0],'doc2')

    def test_partial_indexer_response_never_returns_an_advancing_page(self):
        client=WazuhIndexerClient('https://siem.example','reader','test-only')
        for metadata in ({'timed_out':True},{'_shards':{'failed':1}}):
            response={'hits':{'hits':[self.hit('doc1')]},**metadata}
            with self.subTest(metadata=metadata),patch.object(client,'_request_json',return_value=response):
                accepted=True
                try:client.fetch_alert_page()
                except Exception:accepted=False
                self.assertFalse(accepted,'Partial search cannot establish a lossless cursor')
