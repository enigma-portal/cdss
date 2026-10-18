"""Read-only alert/source presentation for analyst triage.

Alert groups are temporary view models. They never merge source records or
change the separate incident-correlation and risk methodologies.
"""

from datetime import datetime, timezone
from math import ceil
import json

from flask import current_app, has_app_context

from app.services.incident_correlation import event_time
from app.services.alert_parser import stored_reported_account, stored_reported_source_ip, stored_reported_destination_ip


DEFAULT_ALERT_GROUP_WINDOW_MINUTES = 60


ALERT_FROM = """
    FROM alerts al
    LEFT JOIN assets asset ON asset.id = al.asset_id
    LEFT JOIN investigation_case_alerts active_case ON active_case.alert_id = al.id
    LEFT JOIN incident_alerts link ON link.alert_id = al.id
    LEFT JOIN risk_assessments assessment ON assessment.id = (
        SELECT MAX(id) FROM risk_assessments
        WHERE incident_id = COALESCE(active_case.case_id, link.incident_id)
          AND assessment_stage = 'contextual'
    )
    LEFT JOIN investigations investigation ON investigation.id = (
        SELECT MAX(id) FROM investigations
        WHERE incident_id = COALESCE(active_case.case_id, link.incident_id)
          AND playbook_key <> 'wazuh_archive_retrieval_v1'
    )
"""

ALERT_FIELDS = """
    SELECT al.id, al.wazuh_alert_id, al.event_timestamp, al.rule_id,
           al.rule_description, al.rule_level, al.agent_id, al.agent_name,
           al.agent_ip, al.asset_id, al.source_ip, al.destination_ip,
           al.username, al.raw_alert, al.processing_status,
           asset.asset_name, asset.criticality, asset.is_protected,
           COALESCE(active_case.case_id, link.incident_id) AS incident_id,
           active_case.case_id AS active_case_id,
           assessment.id AS assessment_id,
           assessment.evidence_state, investigation.id AS investigation_id,
           CASE WHEN json_valid(al.raw_alert)
                 AND json_type(al.raw_alert, '$.syscheck.path') = 'text'
                THEN json_extract(al.raw_alert, '$.syscheck.path')
           END AS syscheck_path
"""


def source_label(agent_id, agent_name):
    """Identify the reported source without creating or classifying an asset."""
    if agent_id == '000':
        return 'Wazuh Manager (agent 000)'
    return agent_name or (f'Wazuh agent {agent_id}' if agent_id else 'Not reported')


def investigation_status(alert):
    """Describe saved case progress, not whether an alert proves compromise."""
    if alert['assessment_id'] is not None:
        return 'Inconclusive' if alert['evidence_state'] == 'Inconclusive' else 'Assessed'
    if alert['investigation_id'] is not None:
        return 'Investigation Started'
    return 'New'


def _present(alert):
    row = dict(alert)
    if not row['username']:
        row['username'] = stored_reported_account(row['raw_alert'])
    if not row['source_ip']:
        row['source_ip'] = stored_reported_source_ip(row['raw_alert'])
    if not row['destination_ip']:
        row['destination_ip'] = stored_reported_destination_ip(row['raw_alert'])
    row['reported_system'] = source_label(row['agent_id'], row['agent_name'])
    row['investigation_status'] = investigation_status(row)
    return row


def _add_mitre_ids(connection, rows):
    if not rows:
        return rows
    ids = [row['id'] for row in rows]
    for row in rows:
        row['mitre_ids'] = []
        row['wazuh_mitre_ids'] = []
    by_id = {row['id']: row for row in rows}
    for offset in range(0, len(ids), 500):
        chunk = ids[offset:offset + 500]
        placeholders = ','.join('?' for _ in chunk)
        for mapping in connection.execute(f'''
            SELECT alert_id, technique_id, mapping_source FROM alert_mitre_techniques
            WHERE alert_id IN ({placeholders}) ORDER BY alert_id, ordinal, technique_id
        ''', chunk):
            techniques = by_id[mapping['alert_id']]['mitre_ids']
            if mapping['technique_id'] not in techniques:
                techniques.append(mapping['technique_id'])
            if mapping['mapping_source'] == 'wazuh':
                source_ids = by_id[mapping['alert_id']]['wazuh_mitre_ids']
                if mapping['technique_id'] not in source_ids:
                    source_ids.append(mapping['technique_id'])
    return rows


def alert_group_window_minutes():
    """Configurable CDSS display window; invalid values fail to the default."""
    try:
        value = int(current_app.config.get(
            'ALERT_GROUP_WINDOW_MINUTES', DEFAULT_ALERT_GROUP_WINDOW_MINUTES
        )) if has_app_context() else DEFAULT_ALERT_GROUP_WINDOW_MINUTES
        return value if 1 <= value <= 1440 else DEFAULT_ALERT_GROUP_WINDOW_MINUTES
    except (TypeError, ValueError):
        return DEFAULT_ALERT_GROUP_WINDOW_MINUTES


def _group_status(members):
    """Describe the grouped analyst case, not an earlier automatic incident."""
    case_ids = {row['active_case_id'] for row in members if row['active_case_id'] is not None}
    if not case_ids:
        return 'New'
    if len(case_ids) == 1 and all(row['active_case_id'] in case_ids and
                                  row['assessment_id'] is not None for row in members):
        if all(row['evidence_state'] == 'Inconclusive' for row in members):
            return 'Inconclusive'
        return 'Assessed'
    return 'Investigation Started'


def _finalize_group(members, fingerprint):
    """Keep every member ID for later investigation/archive pivots.

    The latest event (UTC time, then CDSS ID) is the deterministic member used
    to open the existing single-case workflow. Other linked cases remain visible
    in the occurrence history; this does not create a multi-alert investigation.
    """
    latest = members[-1]
    case_ids = list(dict.fromkeys(row['incident_id'] for row in members
                                  if row['incident_id'] is not None))
    group = dict(latest)
    # A later sparse event must not hide source identity already reported by an
    # earlier member of this same agent group.
    group['agent_name'] = next((row['agent_name'] for row in reversed(members)
                                if row['agent_name']), None)
    group['agent_ip'] = next((row['agent_ip'] for row in reversed(members)
                              if row['agent_ip']), None)
    group['rule_description'] = next((row['rule_description'] for row in reversed(members)
                                       if row['rule_description']), None)
    group['reported_system'] = source_label(group['agent_id'], group['agent_name'])
    group.update(
        representative_alert_id=latest['id'],
        alert_ids=[row['id'] for row in members],
        members=members,
        fingerprint=fingerprint,
        existing_case_membership=fingerprint.startswith('["existing_case",'),
        occurrences=len(members),
        first_seen=members[0]['event_timestamp'],
        last_seen=latest['event_timestamp'],
        first_seen_utc=event_time(members[0]['event_timestamp']),
        last_seen_utc=event_time(latest['event_timestamp']),
        incident_ids=case_ids,
        fully_assessed=all(row['active_case_id'] is not None and
                           row['assessment_id'] is not None for row in members),
        has_source_ip=any(row['source_ip'] for row in members),
        has_username=any(row['username'] for row in members),
        has_destination_ip=any(row['destination_ip'] for row in members),
        representative_incident_id=next(
            (row['incident_id'] for row in reversed(members)
             if row['incident_id'] is not None), None
        ),
        active_case_id=next((row['active_case_id'] for row in reversed(members)
                             if row['active_case_id'] is not None), None),
        investigation_status=_group_status(members),
    )
    return group


GROUP_SQL = """WITH RECURSIVE
source AS (
    SELECT al.id, cdss_event_us(al.event_timestamp) AS event_us,
           CASE WHEN active_case.case_id IS NOT NULL
                THEN json_array('existing_case',active_case.case_id)
                WHEN al.agent_id IS NULL OR al.agent_id='' OR al.rule_id IS NULL
                     OR al.rule_id='unknown' OR cdss_event_us(al.event_timestamp) IS NULL
                THEN json_array('singleton',al.id)
                ELSE json_array(al.agent_id,al.rule_id,al.rule_level,al.asset_id,
                    COALESCE(NULLIF(al.source_ip,''),CASE WHEN json_valid(al.raw_alert) AND (json_type(al.raw_alert,'$.data.srcip')='text' OR json_type(al.raw_alert,'$.srcip')='text' OR json_type(al.raw_alert,'$.data.win.eventdata.ipAddress')='text' OR json_type(al.raw_alert,'$.data.win.eventdata.sourceIp')='text') THEN cdss_source_ip(al.raw_alert) END),
                    COALESCE(NULLIF(al.username,''),
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.data.win.eventdata.targetUserName')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.data.win.eventdata.targetUserName'),'') END,
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.data.win.eventdata.user')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.data.win.eventdata.user'),'') END),
                    COALESCE(NULLIF(al.destination_ip,''),CASE WHEN json_valid(al.raw_alert) AND (json_type(al.raw_alert,'$.data.dstip')='text' OR json_type(al.raw_alert,'$.data.win.eventdata.destinationIp')='text') THEN cdss_destination_ip(al.raw_alert) END),
                    COALESCE(
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.syscheck.path')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.syscheck.path'),'') END,
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.data.win.eventdata.targetFilename')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.data.win.eventdata.targetFilename'),'') END,
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.data.win.eventdata.processName')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.data.win.eventdata.processName'),'') END,
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.data.win.eventdata.image')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.data.win.eventdata.image'),'') END,
                        CASE WHEN json_valid(al.raw_alert)
                                  AND json_type(al.raw_alert,'$.process.name')='text'
                             THEN NULLIF(json_extract(al.raw_alert,'$.process.name'),'') END))
           END AS fingerprint,
           CASE WHEN ?='' THEN 1 ELSE (
               INSTR(LOWER(COALESCE(al.wazuh_alert_id,'')),LOWER(?))>0 OR
               INSTR(LOWER(COALESCE(al.rule_description,'')),LOWER(?))>0 OR
               INSTR(LOWER(COALESCE(al.agent_name,'')),LOWER(?))>0 OR
               INSTR(LOWER(COALESCE(al.agent_id,'')),LOWER(?))>0) END AS matched
    FROM alerts al
    LEFT JOIN investigation_case_alerts active_case ON active_case.alert_id=al.id
),
ordered AS (
    SELECT *,ROW_NUMBER() OVER (PARTITION BY fingerprint ORDER BY event_us,id) AS rn
    FROM source
),
grouped(fingerprint,rn,id,event_us,matched,group_no,first_us) AS (
    SELECT fingerprint,rn,id,event_us,matched,1,event_us FROM ordered WHERE rn=1
    UNION ALL
    SELECT o.fingerprint,o.rn,o.id,o.event_us,o.matched,
           CASE WHEN json_extract(o.fingerprint,'$[0]')='existing_case'
                     THEN g.group_no
                WHEN o.event_us-g.first_us>? THEN g.group_no+1 ELSE g.group_no END,
           CASE WHEN json_extract(o.fingerprint,'$[0]')='existing_case'
                     THEN g.first_us
                WHEN o.event_us-g.first_us>? THEN o.event_us ELSE g.first_us END
    FROM grouped g JOIN ordered o ON o.fingerprint=g.fingerprint AND o.rn=g.rn+1
),
ranked AS (
    SELECT *,ROW_NUMBER() OVER (
        PARTITION BY fingerprint,group_no ORDER BY event_us DESC,id DESC) AS latest_rank
    FROM grouped
),
summaries AS (
    SELECT fingerprint,group_no,COUNT(*) AS occurrences,MAX(matched) AS matched,
           MAX(event_us) AS last_us,
           MAX(CASE WHEN latest_rank=1 THEN id END) AS representative_id
    FROM ranked GROUP BY fingerprint,group_no
)"""


def _group_sql_parameters(connection, window_minutes, query):
    def epoch(value):
        timestamp=event_time(value)
        return int(timestamp.timestamp()*1_000_000) if timestamp else None
    connection.create_function('cdss_event_us',1,epoch,deterministic=True)
    connection.create_function('cdss_source_ip',1,stored_reported_source_ip,deterministic=True)
    connection.create_function('cdss_destination_ip',1,stored_reported_destination_ip,deterministic=True)
    from app.services.initial_priority import priority_rank
    connection.create_function('cdss_priority_rank', 4, priority_rank, deterministic=True)
    return [query,query,query,query,query,window_minutes*60*1_000_000,
            window_minutes*60*1_000_000]


def _rows_for_member_ids(connection, identifiers):
    rows=[]
    for offset in range(0,len(identifiers),400):
        chunk=identifiers[offset:offset+400]
        placeholders=','.join('?' for _ in chunk)
        rows.extend(_present(row) for row in connection.execute(
            ALERT_FIELDS+ALERT_FROM+f' WHERE al.id IN ({placeholders})',chunk))
    return rows


def _group_from_members(connection, memberships, window_minutes):
    by_id={row['id']:row for row in _rows_for_member_ids(connection,
        [item['id'] for item in memberships])}
    grouped={}
    for item in memberships:
        key=(item['fingerprint'],item['group_no'])
        grouped.setdefault(key,[]).append(by_id[item['id']])
    earliest=datetime.min.replace(tzinfo=timezone.utc)
    result=[]
    for key,members in grouped.items():
        members.sort(key=lambda row:(event_time(row['event_timestamp']) or earliest,row['id']))
        result.append(_finalize_group(members,key[0]))
    result.sort(key=lambda group:(group['last_seen_utc'] or earliest,
                                 group['representative_alert_id']),reverse=True)
    return _add_group_mitre_ids(connection,result)


def _add_group_mitre_ids(connection, groups):
    members = [member for group in groups for member in group['members']]
    _add_mitre_ids(connection, members)
    for group in groups:
        group['mitre_ids'] = list(dict.fromkeys(
            technique for member in group['members']
            for technique in member['mitre_ids']
        ))
        group['wazuh_mitre_ids'] = list(dict.fromkeys(
            technique for member in group['members']
            for technique in member['wazuh_mitre_ids']
        ))
        from app.services.initial_priority import InitialPriority, calculate_initial_priority
        group['group_window_minutes'] = alert_group_window_minutes()
        saved = (connection.execute('''SELECT * FROM initial_alert_priorities
            WHERE incident_id=?''', (group['active_case_id'],)).fetchone()
            if group['existing_case_membership'] and group['active_case_id'] else None)
        if saved:
            try:
                factors = json.loads(saved['factors_json'])
            except (TypeError, ValueError):
                factors = {}
            if not isinstance(factors, dict):
                factors = {}
            group['initial_priority'] = InitialPriority(
                saved['initial_priority'], saved['initial_priority_rationale'],
                saved['initial_priority_model_version'], factors.get('severity_tier'),
                factors.get('asset_criticality'), factors.get('mitre_modifier', 0),
                factors.get('recurrence_modifier', 0),
                factors.get('occurrence_count_used', 0))
        else:
            # A pre-existing case without a snapshot cannot safely claim all
            # mixed historical members are equivalent recurrent detections.
            priority_group = ({**group, 'occurrences': 1}
                              if group['existing_case_membership'] else group)
            group['initial_priority'] = calculate_initial_priority(priority_group, connection)
    return groups


GROUP_CANDIDATES_SQL = ''' ,
        mapping_flags AS (
            SELECT r.fingerprint,r.group_no,1 AS official_mapping
            FROM ranked r
            JOIN alert_mitre_techniques am ON am.alert_id=r.id AND am.mapping_source='wazuh'
            JOIN mitre_techniques mt ON mt.technique_id=am.technique_id
                AND mt.catalogue_source='taxii'
            GROUP BY r.fingerprint,r.group_no
        ),
        candidates AS (
            SELECT s.fingerprint,s.group_no,s.last_us,s.representative_id,s.occurrences,
                   COALESCE(
                     CASE saved.initial_priority
                       WHEN 'Low' THEN 0 WHEN 'Medium' THEN 1
                       WHEN 'High' THEN 2 WHEN 'Critical' THEN 3 END,
                     cdss_priority_rank(a.rule_level,asset.criticality,
                       CASE WHEN json_extract(s.fingerprint,'$[0]')='existing_case'
                            THEN 1 ELSE s.occurrences END,
                       COALESCE(mf.official_mapping,0))) AS sort_priority
            FROM summaries s
            JOIN alerts a ON a.id=s.representative_id
            LEFT JOIN assets asset ON asset.id=a.asset_id
            LEFT JOIN investigation_case_alerts existing ON existing.alert_id=a.id
            LEFT JOIN initial_alert_priorities saved ON saved.incident_id=existing.case_id
            LEFT JOIN mapping_flags mf ON mf.fingerprint=s.fingerprint AND mf.group_no=s.group_no
            WHERE s.matched=1
        )
'''


def list_alerts(connection, args):
    """Page read-only groups; search matches members without narrowing them."""
    query = (args.get('q') or '').strip()[:100]
    sort = args.get('sort') if args.get('sort') in ('priority', 'latest') else 'priority'
    window=alert_group_window_minutes()
    parameters=_group_sql_parameters(connection,window,query)
    counts=connection.execute(GROUP_SQL+'''
        SELECT COUNT(*) AS total,COALESCE(SUM(occurrences),0) AS raw_total
        FROM summaries WHERE matched=1''',parameters).fetchone()
    total=counts['total']
    pages = max(1, ceil(total / 20))
    try:
        page = max(1, min(int(args.get('page', '1')), pages))
    except (TypeError, ValueError):
        page = 1
    ordering = ('COALESCE(sort_priority,-1) DESC,last_us DESC,representative_id DESC'
                if sort == 'priority' else 'last_us DESC,representative_id DESC')
    memberships=[dict(row) for row in connection.execute(GROUP_SQL+GROUP_CANDIDATES_SQL+f''',
        page AS (SELECT fingerprint,group_no FROM candidates
                 ORDER BY {ordering} LIMIT ? OFFSET ?)
        SELECT g.id,g.fingerprint,g.group_no FROM grouped g JOIN page p
          ON g.fingerprint=p.fingerprint AND g.group_no=p.group_no''',
        parameters+[20,(page-1)*20])]
    page_groups=_group_from_members(connection,memberships,window)
    if sort == 'priority':
        from app.services.initial_priority import LABELS
        priority_order = {label: index for index, label in enumerate(LABELS)}
        oldest = datetime.min.replace(tzinfo=timezone.utc)
        page_groups.sort(key=lambda group: (
            priority_order.get(group['initial_priority'].level, -1),
            group['last_seen_utc'] or oldest,
            group['representative_alert_id']), reverse=True)
    pagination = {
        'q': query, 'sort': sort, 'page': page, 'pages': pages, 'total': total,
        'raw_total': counts['raw_total'],
        'page_numbers': list(range(max(1, page - 2), min(pages, page + 2) + 1)),
    }
    return page_groups, pagination


def alert_queue_snapshot(connection, limit=5):
    """Share queue totals and a bounded recent preview; no fake reviewed state."""
    limit = max(1, min(int(limit), 10))
    window = alert_group_window_minutes()
    parameters = _group_sql_parameters(connection, window, '')
    rows = [dict(row) for row in connection.execute(GROUP_SQL+GROUP_CANDIDATES_SQL+""",
        totals AS (
            SELECT COUNT(*) AS total,COALESCE(SUM(occurrences),0) AS raw_total,
                   COALESCE(SUM(sort_priority>=2),0) AS high_priority
            FROM candidates
        ),
        recent AS (SELECT fingerprint,group_no FROM candidates
                   ORDER BY last_us DESC,representative_id DESC LIMIT ?)
        SELECT g.id,g.fingerprint,g.group_no,t.total,t.raw_total,t.high_priority
        FROM totals t LEFT JOIN recent r ON 1=1
        LEFT JOIN grouped g ON g.fingerprint=r.fingerprint AND g.group_no=r.group_no
    """,parameters+[limit])]
    totals = {key: rows[0][key] for key in ('total','raw_total','high_priority')}
    totals['recent'] = _group_from_members(connection,
        [row for row in rows if row['id'] is not None], window)
    return totals


def group_context(connection, member_alert_id):
    """Resolve one member's group in SQLite; only its members enter Python."""
    window=alert_group_window_minutes()
    parameters=_group_sql_parameters(connection,window,'')
    memberships=[dict(row) for row in connection.execute(GROUP_SQL+''',
        target AS (SELECT fingerprint,group_no FROM grouped WHERE id=?)
        SELECT g.id,g.fingerprint,g.group_no FROM grouped g JOIN target t
          ON g.fingerprint=t.fingerprint AND g.group_no=t.group_no''',
        parameters+[member_alert_id])]
    groups=_group_from_members(connection,memberships,window)
    return groups[0] if groups else None


def alert_detail_data(connection, alert_id):
    alert = connection.execute(
        ALERT_FIELDS + ALERT_FROM + ' WHERE al.id = ?', (alert_id,)
    ).fetchone()
    if alert is None:
        return None
    return _add_mitre_ids(connection, [_present(alert)])[0]
