"""Retention preserves all references without scanning every archive per alert."""
import json
import sqlite3
import unittest
import test_soc_triage as fixtures
from app.services.alert_retention import preview_retention
from app.services.investigation import run_investigation


class RetentionHardeningTests(unittest.TestCase):
    setUp=fixtures.SocTriageTests.setUp
    tearDown=fixtures.SocTriageTests.tearDown
    add=fixtures.SocTriageTests.add
    case=fixtures.SocTriageTests.case

    def test_preview_preserves_counts_with_a_bounded_sql_work_budget(self):
        anchor=self.add('anchor')
        case=self.case(anchor)
        execution=run_investigation(case)
        with self.db:
            self.db.executemany('''INSERT INTO alerts(wazuh_alert_id,event_timestamp,rule_id,
                rule_level,agent_id,raw_alert) VALUES(?, '2026-10-09T07:00:00Z','900',12,'001','{}')''',
                [(f'unlinked-{i}',) for i in range(500)])
            self.db.executemany('''INSERT INTO investigation_archive_evidence
                (investigation_id,source_index,source_document_id,event_timestamp,agent_id,short_summary,selected_fields_json)
                VALUES(?,'offline-index',?,'2026-10-09T07:00:00Z','001','offline',?)''',
                [(execution,str(i),json.dumps({'source_alert_id':'unrelated-'+str(i)})) for i in range(1000)])
        callbacks=0
        def budget():
            nonlocal callbacks
            callbacks+=1
            return int(callbacks>2000)
        self.db.set_progress_handler(budget,1000)
        try:
            try:
                result=preview_retention(self.db,{'from':'2026-10-09T07:00','to':'2026-10-09T07:01'})
            except sqlite3.OperationalError as error:
                self.fail(f'Preview exhausted 2 million SQLite operations: {error}')
        finally:
            self.db.set_progress_handler(None,0)
        self.assertEqual((result['eligible'],result['protected']),(500,1))

    def test_reference_to_source_identifier_is_protected(self):
        alert=self.add('source-reference')
        with self.db:
            self.db.execute('CREATE TABLE source_history(source_id TEXT REFERENCES alerts(wazuh_alert_id) ON DELETE CASCADE)')
            self.db.execute("INSERT INTO source_history VALUES('source-reference')")
        result=preview_retention(self.db,{'from':'2026-10-09T07:00','to':'2026-10-09T07:01'})
        self.assertEqual((result['eligible'],result['protected']),(0,1))

    def test_nullable_legacy_source_id_does_not_disappear_from_preview_counts(self):
        anchor=self.add('anchor')
        execution=run_investigation(self.case(anchor))
        with self.db:
            self.db.execute("INSERT INTO alerts(wazuh_alert_id,event_timestamp,rule_id,raw_alert) VALUES(NULL,'2026-10-09T07:00:00Z','900','{}')")
            self.db.execute('''INSERT INTO investigation_archive_evidence
                (investigation_id,source_index,source_document_id,event_timestamp,agent_id,short_summary,selected_fields_json)
                VALUES(?,'offline','doc','2026-10-09T07:00:00Z','001','offline','{"source_alert_id":"unrelated"}')''',(execution,))
        result=preview_retention(self.db,{'from':'2026-10-09T07:00','to':'2026-10-09T07:01'})
        self.assertEqual((result['total'],result['eligible'],result['protected']),(2,1,1))
