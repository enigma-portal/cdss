"""UTC persistence, source provenance and one browser-local display conversion."""
import json
import shutil
import sqlite3
import subprocess
from datetime import datetime, timezone
from pathlib import Path
import unittest
from unittest.mock import Mock, patch

import test_phase2_ingestion as fixtures
from app.database import get_db_connection
from app.services.alert_parser import parse_alert
from app.services.poller import _poll_once
from app.services.siem_collection_status import connector_collection_status
from app.time_utils import parse_timestamp, database_time, source_time, utc_now_text


class TimestampTests(unittest.TestCase):
    def test_legacy_sqlite_utc_is_aware_and_not_server_local(self):
        self.assertEqual(parse_timestamp('2026-10-15 12:02:00', sqlite_utc=True),
                         datetime(2026,10,15,12,2,tzinfo=timezone.utc))
        self.assertIsNone(parse_timestamp('2026-10-15 12:02:00'))

    def test_offsets_and_utc_normalize_to_the_same_instant(self):
        for value in ('2026-10-15T17:02:00+05:00', '2026-10-15T17:02:00+0500',
                      '2026-10-15T12:02:00Z', '2026-10-15T05:02:00-07:00'):
            self.assertEqual(parse_timestamp(value), datetime(2026,10,15,12,2,tzinfo=timezone.utc))

    def test_source_normalization_preserves_the_raw_wazuh_record(self):
        source=fixtures.event();source['timestamp']='2026-10-15T17:02:00+05:00'
        parsed=parse_alert(source)
        self.assertEqual(parsed.event_timestamp,'2026-10-15T12:02:00+00:00')
        self.assertEqual(json.loads(parsed.raw_alert),source)
        source['timestamp']='2026-10-15T17:02:00'
        with self.assertRaisesRegex(ValueError,'explicit timezone'):
            parse_alert(source)

    def test_sqlite_current_timestamp_is_host_utc_not_local(self):
        with sqlite3.connect(':memory:') as db:
            value=db.execute('SELECT CURRENT_TIMESTAMP').fetchone()[0]
        self.assertLess(abs((parse_timestamp(value,sqlite_utc=True)-datetime.now(timezone.utc)).total_seconds()),5)
        self.assertEqual(parse_timestamp(utc_now_text()).utcoffset().total_seconds(),0)
        self.assertTrue(utc_now_text().endswith('Z'))

    def test_server_fallback_is_explicit_utc_with_canonical_machine_time(self):
        html=str(database_time('2026-10-15 12:02:00'))
        self.assertIn('datetime="2026-10-15T12:02:00Z"',html)
        self.assertIn('2026-10-15 12:02:00 UTC',html)
        self.assertEqual(str(source_time('2026-10-15T17:02:00+05:00')),html)
        self.assertNotIn('datetime=',str(source_time('2026-10-15 12:02:00')))
        self.assertIn('&lt;script&gt;',str(database_time('<script>')))
        self.assertEqual(str(database_time(None,'Never')),'Never')

    def browser(self, zone, iso, *, intl=True):
        node=shutil.which('node')
        self.assertIsNotNone(node,'Node is needed to validate the display script')
        script=Path(__file__).resolve().parents[1]/'static/js/timestamps.js'
        runner="""
const fs=require('node:fs'),vm=require('node:vm');
const source=fs.readFileSync(process.argv[1],'utf8');
const zone=process.argv[2],iso=process.argv[3];
const element={textContent:'UTC fallback',getAttribute:k=>k==='datetime'?iso:null};
const context={document:{querySelectorAll:()=>[element]},Date,
  Intl:process.argv[4]==='yes'?{DateTimeFormat:function(locale,options){
    return new Intl.DateTimeFormat('en-GB',{...options,timeZone:zone});
  }}:{}};
vm.runInNewContext(source,context);const first=element.textContent;
vm.runInNewContext(source,context);
console.log(JSON.stringify({first,second:element.textContent,iso}));
"""
        result=subprocess.run([node,'-e',runner,str(script),zone,iso,'yes' if intl else 'no'],
                              capture_output=True,text=True,check=True)
        return json.loads(result.stdout)

    def test_browser_pkt_conversion_once_and_repeat_render_is_idempotent(self):
        result=self.browser('Asia/Karachi','2026-10-15T12:02:00Z')
        self.assertIn('17:02:00 GMT+05:00',result['first'])
        self.assertIn('Asia/Karachi local',result['first'])
        self.assertEqual(result['first'],result['second'])
        self.assertEqual(result['iso'],'2026-10-15T12:02:00Z')

    def test_browser_dst_offsets_remain_explicit(self):
        before=self.browser('America/Los_Angeles','2026-11-01T08:30:00Z')['first']
        after=self.browser('America/Los_Angeles','2026-11-01T09:30:00Z')['first']
        self.assertIn('01:30:00 GMT-07:00',before)
        self.assertIn('01:30:00 GMT-08:00',after)

    def test_browser_never_reinterprets_naive_or_invalid_times(self):
        for value in ('2026-10-15 12:02:00','invalidZ'):
            self.assertEqual(self.browser('Asia/Karachi',value)['first'],'UTC fallback')
        self.assertEqual(self.browser('Asia/Karachi','2026-10-15T12:02:00Z',intl=False)['first'],
                         'UTC fallback')

    def test_display_does_not_conceal_the_wrong_host_clock(self):
        result=self.browser('Asia/Karachi','2026-10-16T00:02:00Z')['first']
        self.assertIn('16/10/2026',result)
        self.assertIn('05:02:00 GMT+05:00',result)
        self.assertNotIn('17:02:00',result)


class ContactTimestampPersistenceTests(unittest.TestCase):
    setUp=fixtures.PhaseTwoIngestionTests.setUp
    tearDown=fixtures.PhaseTwoIngestionTests.tearDown
    add_connector=fixtures.PhaseTwoIngestionTests.add_connector

    def test_poller_write_db_read_status_and_render_preserve_utc(self):
        cid=self.add_connector()
        adapter=Mock();adapter.fetch_event_page.return_value=([fixtures.event()],(123,'doc'))
        instant='2026-10-15T12:02:00Z'
        with (patch('app.services.poller.create_connector',return_value=adapter),
              patch('app.services.poller.unprotect_secret',return_value='test'),
              patch('app.services.poller.utc_now_text',return_value=instant)):
            _poll_once(100,5)
        db=get_db_connection()
        try:
            row=db.execute('SELECT * FROM siem_connections WHERE id=?',(cid,)).fetchone()
            self.assertEqual(row['last_success_at'],instant)
            self.assertEqual(row['last_alert_at'],instant)
            status=connector_collection_status(row,now=parse_timestamp(instant))
            self.assertEqual(status.state,'active')
            self.assertEqual(status.last_success_at,parse_timestamp(instant))
            self.assertIn('datetime="2026-10-15T12:02:00Z"',str(database_time(status.last_success_at)))
            self.assertEqual(db.execute('PRAGMA foreign_key_check').fetchall(),[])
        finally:
            db.close()

    def test_legacy_window_compares_instants_instead_of_offset_strings(self):
        from app.services.incident_processor import _frequency_count
        source=fixtures.event();source['timestamp']='2026-10-15T12:02:00Z'
        parsed=parse_alert(source)
        db=get_db_connection()
        try:
            for value,expected in (('2026-10-15T16:32:00+05:00',2),
                                   ('2026-10-15T11:32:00-04:00',1)):
                with self.subTest(timestamp=value), db:
                    db.execute('DELETE FROM alerts')
                    db.execute("INSERT INTO alerts(wazuh_alert_id,event_timestamp,rule_id,agent_id,username,raw_alert) "
                               "VALUES('historical',?,'5710','001','alice','{}')",(value,))
                    self.assertEqual(_frequency_count(db,parsed),expected)
        finally:
            db.close()
