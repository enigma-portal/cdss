"""Read-only local source-data audit; never initializes runtime storage."""
import hashlib
import json
from pathlib import Path
import sqlite3
import sys
from time import perf_counter

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from app.time_utils import epoch_seconds
from app.services.triage import triage_page, _query


def main():
    path = ROOT/'data'/'cdss.db'
    before = hashlib.sha256(path.read_bytes()).hexdigest()
    connection = sqlite3.connect(path.as_uri()+'?mode=ro',uri=True)
    connection.row_factory=sqlite3.Row
    connection.create_function('cdss_event_epoch',1,epoch_seconds,deterministic=True)
    # mode=ro protects the main file while allowing request-local TEMP summaries.
    connection.execute('BEGIN')
    result={}
    try:
        result['source_alerts']=connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]
        result['repeated_titles']=[dict(r) for r in connection.execute('''SELECT rule_description AS title,
            COUNT(*) AS occurrences,COUNT(DISTINCT agent_id) AS agents,
            COUNT(DISTINCT rule_id) AS rules,COUNT(DISTINCT rule_level) AS levels,
            COUNT(DISTINCT CASE WHEN json_valid(raw_alert) THEN json_extract(raw_alert,'$.syscheck.path') END) AS syscheck_artifacts
            FROM alerts GROUP BY rule_description HAVING COUNT(*)>1 ORDER BY COUNT(*) DESC LIMIT 10''')]
        result['saved_priorities']=[dict(r) for r in connection.execute('SELECT initial_priority,COUNT(*) AS count FROM initial_alert_priorities GROUP BY initial_priority')]
        result['integrity']=[r[0] for r in connection.execute('PRAGMA integrity_check')]
        result['foreign_keys']=[tuple(r) for r in connection.execute('PRAGMA foreign_key_check')]
        result['duplicate_source_ids']=connection.execute('SELECT COUNT(*) FROM (SELECT wazuh_alert_id FROM alerts WHERE wazuh_alert_id IS NOT NULL GROUP BY wazuh_alert_id HAVING COUNT(*)>1)').fetchone()[0]
        result['duplicate_case_memberships']=connection.execute('SELECT COUNT(*) FROM (SELECT alert_id FROM investigation_case_alerts GROUP BY alert_id HAVING COUNT(*)>1)').fetchone()[0]
        result['orphan_case_members']=connection.execute('''SELECT COUNT(*) FROM investigation_case_alerts c
            LEFT JOIN alerts a ON a.id=c.alert_id LEFT JOIN incidents i ON i.id=c.case_id
            WHERE a.id IS NULL OR i.id IS NULL''').fetchone()[0]
        start=perf_counter()
        items,pagination=triage_page(connection,{'view':'needs'})
        result['pending_page_ms']=round((perf_counter()-start)*1000,2)
        result['pending_families']=pagination['total']
        result['pending_top_priorities']=[i['initial_priority'].level for i in items[:6]]
        sql,params,_=_query(connection,{'view':'needs'})
        result['query_plan']=[r[3] for r in connection.execute('EXPLAIN QUERY PLAN '+sql+' SELECT * FROM families ORDER BY priority DESC,last_us DESC,representative_id DESC LIMIT 20',params)]
    finally:
        connection.close()
    result['main_db_bytes_unchanged']=before==hashlib.sha256(path.read_bytes()).hexdigest()
    print(json.dumps(result,indent=2))


if __name__=='__main__':
    main()
