"""SQL-paginated detection families above immutable artifact/case groups.

Family priority is the highest existing child priority, never a new score.
Only artifact identity is relaxed; source, rule, level, account and network
identities remain in the key. UTC fixed windows bound the presentation layer.
"""
from datetime import datetime, timedelta, timezone
from math import ceil
import json

from app.services.alert_view import (
    GROUP_SQL, GROUP_SOURCE_IDENTITY_SQL, GROUP_CANDIDATES_SQL, _group_sql_parameters,
    alert_group_window_minutes, alert_detail_data,
)
from app.services.initial_priority import InitialPriority, calculate_initial_priority
from app.time_utils import parse_timestamp


FAMILY_SQL = """,
    child_context AS (
        SELECT c.*, existing.case_id,
          CASE WHEN existing.case_id IS NOT NULL THEN 'Already Investigated'
               ELSE 'Needs Investigation' END AS triage_status,
          CASE WHEN existing.case_id IS NOT NULL THEN json_array('case',existing.case_id)
               WHEN json_array_length(c.fingerprint)<>8 THEN c.fingerprint
               ELSE json_array(json_extract(c.fingerprint,'$[0]'),
                    json_extract(c.fingerprint,'$[1]'),json_extract(c.fingerprint,'$[2]'),
                    json_extract(c.fingerprint,'$[3]'),json_extract(c.fingerprint,'$[4]'),
                    json_extract(c.fingerprint,'$[5]'),json_extract(c.fingerprint,'$[6]'),
                    CAST(c.last_us / :window_us AS INTEGER)) END AS base_family_key,
          a.agent_id,a.asset_id,
          (SELECT p.case_id FROM temp.cdss_triage_prior p
             WHERE p.identity_key=json_remove(c.fingerprint,'$[7]')
               AND p.event_us<c.first_us AND p.created_us<c.first_us
             ORDER BY p.created_us DESC,p.case_id DESC LIMIT 1) AS prior_case_id
        FROM candidates c JOIN alerts a ON a.id=c.representative_id
        LEFT JOIN investigation_case_alerts existing ON existing.alert_id=a.id
    ),
    children AS (
        SELECT *,CASE WHEN case_id IS NULL THEN json_array(base_family_key,prior_case_id)
                      ELSE base_family_key END AS family_key
        FROM child_context
    )
"""

FAMILY_FILTER_SQL = """,
    filtered AS (
        SELECT * FROM children WHERE
          (:agent='' OR agent_id=:agent_id OR CAST(asset_id AS TEXT)=:asset_id)
          AND (:status='' OR triage_status=:status)
          AND (:view IN ('','all')
            OR (:view='needs' AND case_id IS NULL)
            OR (:view='urgent' AND case_id IS NULL)
            OR (:view='new' AND case_id IS NULL AND prior_case_id IS NOT NULL)
            OR (:view='investigated' AND case_id IS NOT NULL))
    ),
    family_ranked AS (
        SELECT *,ROW_NUMBER() OVER(PARTITION BY family_key ORDER BY
          COALESCE(sort_priority,-1) DESC,last_us DESC,representative_id DESC) AS family_rank
        FROM filtered
    ),
    family_summaries AS (
        SELECT family_key,MAX(sort_priority) AS priority,MAX(last_us) AS last_us,MIN(first_us) AS first_us,
          SUM(occurrences) AS occurrences,COUNT(*) AS child_count,
          MAX(case_id) AS case_id,MAX(prior_case_id) AS prior_case_id,
          MAX(CASE WHEN family_rank=1 THEN representative_id END) AS representative_id
        FROM family_ranked GROUP BY family_key
    ),
    families AS (
        SELECT * FROM family_summaries WHERE
          (:priority='' OR COALESCE(priority,-1)=:priority_rank)
          AND (:view<>'urgent' OR priority>=2)
    )
"""


def _query(connection, args):
    window = alert_group_window_minutes()
    query = (args.get('q') or '').strip()[:100]
    positional = _group_sql_parameters(connection, window, query)
    # Named parameters keep the shared recursive query auditable.
    sql = GROUP_SQL + GROUP_CANDIDATES_SQL
    for index in range(len(positional)):
        sql = sql.replace('?', ':p' + str(index), 1)
    params = {'p' + str(i): value for i, value in enumerate(positional)}
    period = args.get('period', '')
    start = end = None
    error = None
    try:
        if period in ('15m', '1h', '24h'):
            end = datetime.now(timezone.utc)
            start = end - timedelta(minutes={'15m': 15, '1h': 60, '24h': 1440}[period])
        elif period == 'custom':
            def parse_bound(key):
                value = datetime.fromisoformat(args.get(key, ''))
                return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value
            start, end = (parse_bound(key) for key in ('from','to'))
            if start > end:
                raise ValueError()
    except (ValueError, TypeError):
        error = 'Enter a valid From/To range in UTC, with From before To.'
    params.update(start=int(start.timestamp()*1_000_000) if start else None,
                  end=int(end.timestamp()*1_000_000) if end else None)
    sql = sql.replace('END AS matched', 'END AND (:start IS NULL OR cdss_event_us(al.event_timestamp)>=:start) '
                      'AND (:end IS NULL OR cdss_event_us(al.event_timestamp)<=:end) AS matched')
    if error:
        sql = sql.replace('AS matched', 'AND 0 AS matched', 1)
    priority = args.get('priority', '')
    labels = {'Low': 0, 'Medium': 1, 'High': 2, 'Critical': 3, 'Not Assessed': -1}
    agent = args.get('agent','')[:100]
    params.update(window_us=window*60*1_000_000, priority=priority,
                  priority_rank=labels.get(priority, -2), agent=agent,
                  agent_id=agent.removeprefix('agent:') if not agent.startswith('asset:') else None,
                  asset_id=agent.removeprefix('asset:') if not agent.startswith('agent:') else None,
                  status=args.get('status', ''), view=args.get('view', 'all'))
    return sql + FAMILY_SQL + FAMILY_FILTER_SQL, params, error


def filter_options(connection):
    """Names for analyst filters; IDs are only form values."""
    options = [('asset:'+str(r['id']), 'Asset: '+r['asset_name']) for r in connection.execute(
        'SELECT id,asset_name FROM assets ORDER BY asset_name LIMIT 500')]
    options.extend(('agent:'+r['agent_id'], 'Wazuh source: '+(r['agent_name'] or r['agent_id']))
        for r in connection.execute("SELECT agent_id,MAX(agent_name) AS agent_name FROM alerts WHERE agent_id IS NOT NULL GROUP BY agent_id ORDER BY agent_name LIMIT 500"))
    return options


def _materialize(connection, sql, params):
    """Evaluate recursive grouping once per request, entirely inside SQLite.

    Only compact group summaries enter TEMP storage. No raw alert table is
    loaded into Python, and nothing is persisted to the application database.
    """
    # Normalize prior members with exactly the same identity expression as live
    # groups. This also recovers accounts/IPs from historical source fields.
    def database_epoch_us(value):
        timestamp = parse_timestamp(value, sqlite_utc=True)
        return int(timestamp.timestamp()*1_000_000) if timestamp else None

    connection.create_function('cdss_database_us', 1, database_epoch_us, deterministic=True)
    connection.execute('DROP TABLE IF EXISTS temp.cdss_triage_prior')
    expression = GROUP_SOURCE_IDENTITY_SQL
    connection.execute('''CREATE TEMP TABLE cdss_triage_prior AS
        SELECT link.case_id,cdss_event_us(al.event_timestamp) AS event_us,
          cdss_database_us(ci.created_at) AS created_us,
          json_remove(''' + expression + ''','$[7]') AS identity_key
        FROM investigation_case_alerts link JOIN alerts al ON al.id=link.alert_id
        JOIN incidents ci ON ci.id=link.case_id''')
    connection.execute('CREATE INDEX temp.cdss_triage_prior_key ON cdss_triage_prior(identity_key,created_us DESC)')
    connection.execute('DROP TABLE IF EXISTS temp.cdss_triage_children')
    connection.execute('CREATE TEMP TABLE cdss_triage_children AS ' +
                       sql + ' SELECT * FROM children', params)
    connection.execute('CREATE INDEX temp.cdss_triage_family ON cdss_triage_children(family_key)')
    connection.execute('CREATE INDEX temp.cdss_triage_representative ON cdss_triage_children(representative_id)')
    return _cached_query()


def _cached_query():
    return 'WITH children AS (SELECT * FROM temp.cdss_triage_children)' + FAMILY_FILTER_SQL


def _present(connection, row, sql, params):
    item = alert_detail_data(connection, row['representative_id'])
    item.update(row)
    item['representative_alert_id'] = row['representative_id']
    child = connection.execute(sql + ' SELECT * FROM children WHERE representative_id=:rep',
                               {**params, 'rep': row['representative_id']}).fetchone()
    item['group_occurrences'] = child['occurrences']
    identity = json.loads(child['fingerprint'])
    item['artifact'] = identity[7] if len(identity)==8 else None
    item['group_window_minutes'] = alert_group_window_minutes()
    item['last_seen'] = datetime.fromtimestamp(row['last_us']/1_000_000, timezone.utc).isoformat() if row['last_us'] else item['event_timestamp']
    item['first_seen'] = row['first_us']
    if item['first_seen']:
        item['first_seen'] = datetime.fromtimestamp(item['first_seen']/1_000_000, timezone.utc).isoformat()
    # The methodology uses a binary official mapping flag. This ID is an actual
    # qualifying member mapping selected by the shared SQL calculation.
    item['wazuh_mitre_ids'] = [child['official_technique_id']] if child['official_technique_id'] else []
    saved = connection.execute('SELECT * FROM initial_alert_priorities WHERE incident_id=?',
                               (row['case_id'],)).fetchone() if row['case_id'] else None
    if saved:
        item['initial_priority'] = InitialPriority(saved['initial_priority'], saved['initial_priority_rationale'])
    else:
        item['initial_priority'] = calculate_initial_priority(
            {**item, 'occurrences': 1 if row['case_id'] else child['occurrences']}, connection)
    item['prior_case'] = (dict(case) if (case := connection.execute(
        '''SELECT i.id,i.status,(SELECT evidence_state FROM risk_assessments
            WHERE incident_id=i.id AND assessment_stage='contextual' ORDER BY id DESC LIMIT 1) AS evidence_state
            FROM incidents i WHERE i.id=?''', (row['prior_case_id'],)).fetchone()) else None)
    if row['case_id']:
        item['investigation_status'] = connection.execute('''SELECT CASE
            WHEN EXISTS(SELECT 1 FROM risk_assessments WHERE incident_id=:case_id AND assessment_stage='contextual')
              THEN COALESCE((SELECT evidence_state FROM risk_assessments WHERE incident_id=:case_id
                             AND assessment_stage='contextual' ORDER BY id DESC LIMIT 1),'Assessed')
            ELSE 'Investigation Started' END''', {'case_id':row['case_id']}).fetchone()[0]
    else:
        item['investigation_status'] = 'Pending Investigation'
    item['priority_reason'] = priority_reason(item)
    return item



def priority_reason(item):
    """Short explanation of the existing priority, never a new calculation."""
    priority = item['initial_priority']
    if item.get('case_id'):
        return 'Initial priority saved when this investigation was opened.'
    if priority.level is None:
        return priority.rationale
    context = []
    if priority.mitre_modifier:
        context.append('mapped ATT&CK context')
    if priority.recurrence_modifier:
        context.append('repeated activity')
    reason = f"Wazuh level {item['rule_level']} and {priority.asset_criticality} asset criticality"
    if context:
        reason += ', with ' + ' and '.join(context)
    return reason + '.'


QUICK_VIEWS = (('needs', 'Needs Investigation'), ('urgent', 'Critical + High'),
               ('new', 'New Activity'), ('investigated', 'Already Investigated'), ('all', 'All'))


def resolve_filters(args):
    values = dict(args)
    view, status = values.get('view', 'all'), values.get('status', '')
    incompatible = ((view in ('needs', 'urgent', 'new') and status == 'Already Investigated')
                    or (view == 'investigated' and status == 'Needs Investigation')
                    or (view == 'urgent' and values.get('priority') not in (None, '', 'High', 'Critical')))
    if incompatible:
        values['view'] = 'all'
        return values, 'Quick view reset to All to match your selected filters.'
    return values, None


def quick_views(args):
    result = []
    for value, label in QUICK_VIEWS:
        values = {key: args[key] for key in ('q', 'priority', 'agent', 'period', 'from', 'to', 'sort') if args.get(key)}
        if value == 'urgent' and values.get('priority') not in ('High', 'Critical'):
            values.pop('priority', None)
        values.update(view=value, page=1)
        result.append(dict(value=value, label=label, args=values))
    return result


def triage_page(connection, args):
    args, filter_notice = resolve_filters(args)
    sql, params, error = _query(connection, args)
    sql = _materialize(connection, sql, params)
    count = connection.execute(sql + ' SELECT COUNT(*),COALESCE(SUM(occurrences),0) FROM families', params).fetchone()
    pages = max(1, ceil(count[0]/20))
    try:
        page = max(1, min(pages, int(args.get('page', 1))))
    except (ValueError, TypeError):
        page = 1
    ordering = ('last_us DESC,representative_id DESC' if args.get('sort') == 'latest' else
                'CASE WHEN case_id IS NULL THEN 0 ELSE 1 END,COALESCE(priority,-1) DESC,last_us DESC,representative_id DESC')
    rows = connection.execute(sql + f' SELECT * FROM families ORDER BY {ordering} LIMIT :limit OFFSET :offset',
                              {**params, 'limit': 20, 'offset': (page-1)*20}).fetchall()
    items = [_present(connection, dict(row), sql, params) for row in rows]
    pagination = {key: args.get(key, '') for key in ('q','sort','period','from','to','priority','agent','status','view')}
    pagination.update(page=page, pages=pages, total=count[0], raw_total=count[1], time_error=error,
                      page_numbers=list(range(max(1,page-2),min(pages,page+2)+1)),
                      filter_notice=filter_notice, quick_views=quick_views(args))
    return items, pagination


def triage_overview(connection, period='24h'):
    items, _ = triage_page(connection, {'view': 'needs'})
    sql, params, _ = _query(connection, {'view': 'needs'})
    sql = _cached_query()
    counts = {row[0]: row[1] for row in connection.execute(sql +
        ' SELECT priority,COUNT(*) FROM families GROUP BY priority', params)}
    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes={'15m':15,'1h':60,'24h':1440}[period])
    recent = connection.execute('''SELECT COUNT(*) FROM (
        SELECT family_key,MIN(first_us) AS first_event FROM temp.cdss_triage_children
        GROUP BY family_key HAVING first_event BETWEEN ? AND ?)''',
        (int(start.timestamp()*1_000_000),int(now.timestamp()*1_000_000))).fetchone()[0]
    return dict(queue=items[:6], critical=counts.get(3,0), high=counts.get(2,0),
                medium=counts.get(1,0), recent=recent, period=period,
                active=connection.execute("SELECT COUNT(*) FROM incidents WHERE case_origin='analyst_group' AND status IN ('open','investigating')").fetchone()[0])


def family_children(connection, alert_id, args):
    sql, params, _ = _query(connection, {})
    sql = _materialize(connection, sql, params)
    # A rendered family URL remains valid when a later occurrence replaces its
    # representative. Resolve the supplied source member through current groups.
    window = alert_group_window_minutes()
    group_params = _group_sql_parameters(connection, window, '')
    target = connection.execute(GROUP_SQL + '''
        SELECT t.family_key FROM grouped g JOIN temp.cdss_triage_children t
          ON t.fingerprint=g.fingerprint AND t.group_no=g.group_no
        WHERE g.id=?''', group_params + [alert_id]).fetchone()
    if target is None:
        return None
    try:
        page = max(1, int(args.get('page',1)))
    except (TypeError, ValueError):
        page = 1
    params.update(family=target[0], offset=(page-1)*20)
    total = connection.execute(sql + ' SELECT COUNT(*) FROM children WHERE family_key=:family', params).fetchone()[0]
    rows = connection.execute(sql + ''' SELECT family_key,sort_priority AS priority,last_us,first_us,
        occurrences,1 AS child_count,case_id,prior_case_id,representative_id FROM children
        WHERE family_key=:family ORDER BY COALESCE(sort_priority,-1) DESC,last_us DESC,representative_id DESC
        LIMIT 20 OFFSET :offset''', params).fetchall()
    return dict(items=[_present(connection,dict(row),sql,params) for row in rows], page=page,
                pages=max(1,ceil(total/20)), total=total)
