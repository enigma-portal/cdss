"""Preview and atomic purge of source alerts without investigation references."""
from datetime import datetime, timezone
import hashlib
import json


def migrate_retention(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS alert_retention_audit (
        id INTEGER PRIMARY KEY, actor_user_id INTEGER NOT NULL REFERENCES users(id),
        performed_at TEXT NOT NULL, range_from TEXT NOT NULL, range_to TEXT NOT NULL,
        agent_filter TEXT NOT NULL, status_filter TEXT NOT NULL,
        deleted_count INTEGER NOT NULL, protected_count INTEGER NOT NULL)''')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_alerts_event_epoch
        ON alerts(cdss_event_epoch(event_timestamp))''')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_alerts_agent_rule
        ON alerts(agent_id,rule_id,event_timestamp)''')


def _quote(value):
    return '"' + value.replace('"','""') + '"'


def protected_sql(connection):
    """Discover direct references, including SET NULL/CASCADE audit links.

    Alert ATT&CK mappings alone are disposable; incident provenance referencing
    those mappings is protected explicitly. Future direct FK references default
    to protected, rather than depending on their delete action.
    """
    clauses = []
    tables = [r[0] for r in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")]
    for table in tables:
        if table == 'alert_mitre_techniques':
            continue
        for fk in connection.execute('PRAGMA foreign_key_list(' + _quote(table) + ')'):
            if fk['table'] == 'alerts':
                clauses.append(f'EXISTS(SELECT 1 FROM {_quote(table)} ref WHERE ref.{_quote(fk["from"])}=al.id)')
    if 'incident_mitre_sources' in tables:
        clauses.append('EXISTS(SELECT 1 FROM incident_mitre_sources ref WHERE ref.source_alert_id=al.id)')
    # Archive copies may refer to source Wazuh IDs rather than CDSS foreign keys.
    if 'investigation_archive_evidence' in tables:
        columns = {r['name'] for r in connection.execute('PRAGMA table_info(investigation_archive_evidence)')}
        if 'selected_fields_json' in columns:
            clauses.append("EXISTS(SELECT 1 FROM investigation_archive_evidence ref WHERE json_valid(ref.selected_fields_json) AND CAST(json_extract(ref.selected_fields_json,'$.source_alert_id') AS TEXT)=al.wazuh_alert_id)")
    return '(' + ' OR '.join(clauses or ['0']) + ')'


def selection(values):
    try:
        bounds = []
        for key in ('from','to'):
            value = datetime.fromisoformat(values.get(key, ''))
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            bounds.append(value.astimezone(timezone.utc))
        if bounds[0] > bounds[1]:
            raise ValueError()
    except (TypeError, ValueError):
        raise ValueError('Select a valid event-time From/To range in UTC.') from None
    status = values.get('status', '')
    if status not in ('', 'unlinked', 'linked'):
        raise ValueError('Select a valid investigation status.')
    return dict(start=bounds[0].isoformat(), end=bounds[1].isoformat(),
                agent=values.get('agent', '').strip()[:100], status=status)


def _preview(connection, chosen):
    protected = protected_sql(connection)
    sql = f'''SELECT al.id,al.event_timestamp,al.agent_id,al.rule_id,{protected} AS protected
        FROM alerts al WHERE cdss_event_epoch(al.event_timestamp) BETWEEN
          cdss_event_epoch(:start) AND cdss_event_epoch(:end)
          AND (:agent='' OR al.agent_id=CASE WHEN substr(:agent,1,6)='asset:' THEN NULL
                WHEN substr(:agent,1,6)='agent:' THEN substr(:agent,7) ELSE :agent END
              OR CAST(al.asset_id AS TEXT)=CASE WHEN substr(:agent,1,6)='agent:' THEN NULL
                WHEN substr(:agent,1,6)='asset:' THEN substr(:agent,7) ELSE :agent END)'''
    sql += (f' AND {protected}' if chosen['status']=='linked' else
            f' AND NOT {protected}' if chosen['status']=='unlinked' else '')
    summary = dict(connection.execute('''WITH selected AS (''' + sql + ''')
        SELECT COUNT(*) AS total,COALESCE(SUM(NOT protected),0) AS eligible,
          COALESCE(SUM(protected),0) AS protected,
          MIN(cdss_event_epoch(event_timestamp)) AS oldest,
          MAX(cdss_event_epoch(event_timestamp)) AS newest,
          COUNT(DISTINCT json_array(agent_id,rule_id)) AS affected_families
        FROM selected''', chosen).fetchone())
    from app.services.alert_view import GROUP_SQL, _group_sql_parameters, alert_group_window_minutes
    group_params = _group_sql_parameters(connection, alert_group_window_minutes(), '')
    group_sql = GROUP_SQL
    named = {}
    for index, value in enumerate(group_params):
        key = 'group_param_' + str(index)
        group_sql = group_sql.replace('?', ':' + key, 1)
        named[key] = value
    summary['affected_groups'] = connection.execute(group_sql + ', selected AS (' + sql + ''')
        SELECT COUNT(DISTINCT json_array(g.fingerprint,g.group_no))
        FROM grouped g JOIN selected s ON s.id=g.id''', {**named, **chosen}).fetchone()[0]
    # Token binds the exact preview selection without retaining deleted content.
    digest = hashlib.sha256(json.dumps(chosen,sort_keys=True).encode())
    for row in connection.execute(sql + ' ORDER BY al.id', chosen):
        digest.update(f'{row["id"]}:{row["protected"]};'.encode())
    summary['token'] = digest.hexdigest()
    summary['remaining'] = connection.execute('SELECT COUNT(*) FROM alerts').fetchone()[0]-summary['eligible']
    for key in ('oldest','newest'):
        summary[key] = datetime.fromtimestamp(summary[key],timezone.utc).isoformat() if summary[key] is not None else None
    return summary, sql


def preview_retention(connection, values):
    chosen = selection(values)
    with connection:
        # One snapshot for all preview counts and the confirmation token.
        connection.execute('BEGIN')
        return _preview(connection, chosen)[0]


def purge_retention(connection, values, actor_id, token):
    chosen = selection(values)
    with connection:
        connection.execute('BEGIN IMMEDIATE')
        actor = connection.execute("SELECT role,is_active FROM users WHERE id=?",(actor_id,)).fetchone()
        if not actor or actor['role']!='admin' or not actor['is_active']:
            raise PermissionError('Administrator access required.')
        result, sql = _preview(connection, chosen)
        if result['token'] != token:
            raise ValueError('Alerts changed since preview. Preview again before confirming.')
        cursor = connection.execute('DELETE FROM alerts WHERE id IN (SELECT id FROM (' + sql + ') WHERE NOT protected)', chosen)
        if cursor.rowcount != result['eligible']:
            raise RuntimeError('Retention count mismatch')
        connection.execute('''INSERT INTO alert_retention_audit
            (actor_user_id,performed_at,range_from,range_to,agent_filter,status_filter,deleted_count,protected_count)
            VALUES(?,?,?,?,?,?,?,?)''', (actor_id,datetime.now(timezone.utc).isoformat(),chosen['start'],chosen['end'],
              chosen['agent'],chosen['status'],cursor.rowcount,result['protected']))
        if connection.execute('PRAGMA foreign_key_check').fetchone():
            raise RuntimeError('Foreign-key integrity check failed; purge rolled back')
        return result
