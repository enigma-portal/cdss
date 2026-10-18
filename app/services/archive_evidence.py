"""Bounded, read-only Wazuh archive retrieval for a grouped-alert investigation.

This is evidence collection, not a playbook, assessment, or compromise verdict.
Only allowlisted source fields and provenance are persisted; full archive
documents remain on the SIEM. Existing alert ingestion is untouched.
"""

import json
import ipaddress
from datetime import timedelta

from flask import current_app

from app.database import get_db_connection
from app.services.alert_view import group_context, source_label
from app.services.connectors import create_connector
from app.services.incident_correlation import event_time
from app.services.mitre_mapping import attach_alert_context
from app.services.playbook_registry import PLAYBOOKS, imported_definition, select_playbook
from app.services.imported_playbooks import imported_playbook
from app.services.secret_store import SecretProtectionError, unprotect_secret
from app.services.wazuh_indexer import WazuhIndexerError


ARCHIVE_PLAYBOOK = 'wazuh_archive_retrieval_v1'
ARCHIVE_INDEX = 'wazuh-archives-*'
DEFAULT_BUFFER_MINUTES = 10
DEFAULT_MAX_EVENTS = 200
FIELD_CANDIDATES = ('timestamp', '@timestamp', 'agent.id', 'agent.id.keyword')
SOURCE_FIELDS = (
    'id', 'timestamp', '@timestamp', 'agent.id', 'agent.name', 'rule.id',
    'rule.description', 'rule.level', 'rule.groups', 'decoder.name', 'location', 'data.srcip',
    'data.dstip', 'data.srcuser', 'data.dstuser', 'data.user',
    'data.win.eventdata.ipAddress', 'data.win.eventdata.targetUserName',
    'data.win.eventdata.sourceIp', 'data.win.eventdata.destinationIp',
    'data.win.system.eventID', 'data.win.system.eventId',
    'data.win.eventdata.processName', 'data.win.eventdata.parentProcessName',
    'data.win.eventdata.image', 'data.win.eventdata.parentImage',
    'data.win.eventdata.targetFilename', 'data.win.eventdata.user',
    'data.win.eventdata.processId', 'data.win.eventdata.commandLine',
    'data.win.eventdata.hashes', 'process.name', 'process.parent.name',
    'process.pid', 'process.command_line', 'syscheck.path',
    'syscheck.md5_after', 'syscheck.sha256_after',
)
SELECTED_FIELDS = {
    'source_alert_id': ('id',),
    'rule_id': ('rule.id',),
    'rule_description': ('rule.description',),
    'source_ip': ('data.srcip',),
    'destination_ip': ('data.dstip',),
    'username': ('data.srcuser', 'data.dstuser', 'data.user',
                 'data.win.eventdata.targetUserName', 'data.win.eventdata.user'),
    'event_id': ('data.win.system.eventID', 'data.win.system.eventId'),
    'process_name': ('process.name', 'data.win.eventdata.processName', 'data.win.eventdata.image'),
    'parent_process': ('process.parent.name', 'data.win.eventdata.parentProcessName',
                       'data.win.eventdata.parentImage'),
    'process_id': ('process.pid', 'data.win.eventdata.processId'),
    'command_line': ('process.command_line', 'data.win.eventdata.commandLine'),
    'hashes': ('data.win.eventdata.hashes', 'syscheck.md5_after', 'syscheck.sha256_after'),
    'file_path': ('syscheck.path', 'data.win.eventdata.targetFilename'),
    'location': ('location',),
}


class ArchiveUnavailable(RuntimeError):
    """Archive index, mapping or selected connector is currently unavailable."""


class ArchiveInvalid(RuntimeError):
    """The source returned a malformed or incomplete bounded result."""


def _bounded_setting(name, default, maximum):
    try:
        value = int(current_app.config.get(name, default))
        return value if 1 <= value <= maximum else default
    except (TypeError, ValueError):
        return default


def _field(source, dotted):
    if not isinstance(source, dict):
        return None
    if dotted in source:
        return source[dotted]
    value = source
    for part in dotted.split('.'):
        if not isinstance(value, dict):
            return None
        value = value.get(part)
    return value


def _text(value, limit=512):
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        return None
    result = str(value).strip()
    if not result:
        return None
    return result if len(result) <= limit else result[:limit] + '… [truncated]'


def _selected(source):
    selected = {}
    for label, paths in SELECTED_FIELDS.items():
        for path in paths:
            value = _text(_field(source, path), 512 if label == 'command_line' else 256)
            if value is not None:
                selected[label] = value
                break
    groups = _field(source, 'rule.groups')
    if isinstance(groups, list) and len(groups) <= 32 and all(
            isinstance(group, str) and 0 < len(group) <= 64 for group in groups):
        selected['rule_groups'] = groups
    level = _field(source, 'rule.level')
    if type(level) is int and 0 <= level <= 16:
        selected['rule_level'] = level
    if 'source_ip' not in selected:
        from app.services.alert_parser import reported_source_ip
        value = reported_source_ip(source)
        if value:
            selected['source_ip'] = value
    if 'destination_ip' not in selected:
        from app.services.alert_parser import reported_destination_ip
        value = reported_destination_ip(source)
        if value:
            selected['destination_ip'] = value
    return selected


def _group_pivots(connection, group):
    pivots = {'mitre_ids': group['mitre_ids']}
    for label, column in (('source_ip', 'source_ip'), ('username', 'username'),
                          ('destination_ip', 'destination_ip'), ('file_path', 'syscheck_path')):
        value = next((row[column] for row in group['members'] if row[column]), None)
        if value:
            pivots[label] = value
    collected = {}
    for offset in range(0, len(group['alert_ids']), 500):
        ids = group['alert_ids'][offset:offset + 500]
        placeholders = ','.join('?' for _ in ids)
        for row in connection.execute(
            f'SELECT raw_alert FROM alerts WHERE id IN ({placeholders})', ids
        ):
            try:
                source = json.loads(row['raw_alert'])
            except (TypeError, ValueError):
                continue
            if not isinstance(source, dict):
                continue
            for label, value in _selected(source).items():
                if label in ('process_name', 'parent_process', 'process_id',
                             'command_line', 'hashes', 'event_id', 'file_path'):
                    values = collected.setdefault(label, [])
                    if value not in values and len(values) < 10:
                        values.append(value)
            groups = _field(source, 'rule.groups')
            if isinstance(groups, list):
                values = collected.setdefault('rule_groups', [])
                for value in groups:
                    text = _text(value, 64)
                    if text and text not in values and len(values) < 20:
                        values.append(text)
    return pivots | {key: value for key, value in collected.items()
                     if value and key not in pivots}


def _mapped_field(capabilities, names, allowed_types):
    fields = capabilities.get('fields') if isinstance(capabilities, dict) else None
    if not isinstance(fields, dict) or not capabilities.get('indices'):
        raise ArchiveUnavailable('Archive index mapping is unavailable.')
    for name in names:
        types = fields.get(name)
        if (not isinstance(types, dict) or not types or
                not set(types).issubset(allowed_types)):
            continue
        if all(isinstance(info, dict) and info.get('searchable') is True and
               info.get('aggregatable') is True and not info.get('non_searchable_indices') and
               not info.get('non_aggregatable_indices') for info in types.values()):
            return name
    raise ArchiveUnavailable('Required archive field mapping is unavailable.')


def _archive_fields(client):
    capabilities = client.field_capabilities(FIELD_CANDIDATES)
    timestamp = _mapped_field(capabilities, ('timestamp', '@timestamp'),
                              {'date', 'date_nanos'})
    agent = _mapped_field(capabilities, ('agent.id', 'agent.id.keyword'),
                          {'keyword', 'constant_keyword'})
    return timestamp, agent


def _nearest_sort(time_field, first, last):
    return [
            {'_script': {'type': 'number', 'order': 'asc', 'script': {
                'lang': 'painless',
                'source': ('long t = doc[params.field].value.toInstant().toEpochMilli(); '
                           'return Math.min(Math.abs(t - params.first), Math.abs(t - params.last));'),
                'params': {'field': time_field,
                           'first': int(first.timestamp() * 1000),
                           'last': int(last.timestamp() * 1000)},
            }}},
            {time_field: {'order': 'asc'}},
            {'_index': {'order': 'asc'}},
            {'_id': {'order': 'asc'}},
        ]


def _query(client, group, start, end, max_events):
    time_field, agent_field = _archive_fields(client)
    # Rank within the unchanged source-time window before applying the hard cap.
    # Both endpoints matter: earliest-first loses the trigger under noisy prelude
    # telemetry, while latest-first can lose the first grouped observation.
    first = group['first_seen_utc']
    last = group['last_seen_utc']
    if first is None or last is None or not start <= first <= last <= end:
        raise ArchiveUnavailable('Trigger timestamps are unavailable or outside the investigation window.')
    payload = {
        'size': max_events,
        'track_total_hits': True,
        '_source': list(SOURCE_FIELDS),
        'query': {'bool': {'filter': [
            {'term': {agent_field: group['agent_id']}},
            {'range': {time_field: {'gte': start.isoformat(), 'lte': end.isoformat()}}},
        ]}},
        'sort': _nearest_sort(time_field, first, last),
    }
    response = client.search_documents(payload)
    if not isinstance(response, dict) or response.get('timed_out') is True:
        raise ArchiveInvalid('Archive search did not return a complete response.')
    shards = response.get('_shards')
    if isinstance(shards, dict) and shards.get('failed', 0):
        raise ArchiveInvalid('Archive search reported shard failures.')
    hits_object = response.get('hits')
    hits = hits_object.get('hits') if isinstance(hits_object, dict) else None
    if not isinstance(hits, list) or len(hits) > max_events:
        raise ArchiveInvalid('Archive search returned malformed hits.')
    total = hits_object.get('total')
    inexact_total = False
    if isinstance(total, dict):
        total_hits = total.get('value')
        inexact_total = total.get('relation') != 'eq'
    elif type(total) is int:
        total_hits = total
    else:
        total_hits = None
    if total_hits is not None and (type(total_hits) is not int or total_hits < len(hits)):
        raise ArchiveInvalid('Archive search returned an invalid total count.')
    evidence = []
    seen = set()
    for hit in hits:
        if not isinstance(hit, dict) or not isinstance(hit.get('_source'), dict):
            raise ArchiveInvalid('Archive search returned a malformed document.')
        index, document_id = hit.get('_index'), hit.get('_id')
        if not isinstance(index, str) or not index.startswith('wazuh-archives-') or not isinstance(document_id, str) or not document_id:
            raise ArchiveInvalid('Archive document provenance is incomplete.')
        if (index, document_id) in seen:
            raise ArchiveInvalid('Archive search returned duplicate document identifiers.')
        seen.add((index, document_id))
        source = hit['_source']
        # A keyword multi-field is not normally present in _source; inspect its
        # underlying agent.id value, not an invented value from the query.
        reported_agent = _text(_field(source, 'agent.id'), 64)
        timestamp = _text(_field(source, time_field), 100)
        observed = event_time(timestamp)
        if reported_agent != group['agent_id'] or observed is None or not start <= observed <= end:
            raise ArchiveInvalid('Archive document does not match the bounded source query.')
        selected = _selected(source)
        description = _text(_field(source, 'rule.description'), 256)
        decoder = _text(_field(source, 'decoder.name'), 128)
        event_id = selected.get('event_id')
        summary = description or decoder or (f'Event ID {event_id}' if event_id else 'Wazuh archive event')
        evidence.append(dict(source_index=index, source_document_id=document_id,
                             event_timestamp=observed.isoformat(), agent_id=reported_agent,
                             event_type=decoder or event_id, short_summary=summary,
                             selected_fields=selected, observed_utc=observed))
    evidence.sort(key=lambda item: (item['observed_utc'], item['source_index'],
                                    item['source_document_id']))
    truncated = (total_hits > len(evidence) if total_hits is not None else
                 len(evidence) == max_events) or inexact_total
    return (time_field, agent_field, evidence, total_hits,
            not inexact_total if total_hits is not None else None, truncated)


def _cross_address(value):
    try:
        address = ipaddress.ip_address(value)
        address = getattr(address, 'ipv4_mapped', None) or address
        if (address.is_loopback or address.is_unspecified or address.is_multicast
                or address.is_link_local or str(address) == '255.255.255.255'):
            return None
        return address
    except (ValueError, TypeError):
        return None


def _query_cross_asset(client, group, pivots, start, end, max_events, time_field, agent_field):
    """Bounded cross-system context, with verified source/account and coverage."""
    source_ip, username = pivots.get('source_ip'), pivots.get('username')
    address = _cross_address(source_ip)
    if address is None or not username:
        raise ArchiveUnavailable('A meaningful observed network source and account are required.')
    ip_paths = ('data.srcip', 'data.win.eventdata.ipAddress', 'data.win.eventdata.sourceIp')
    account_paths = ('data.srcuser', 'data.dstuser', 'data.user',
                     'data.win.eventdata.targetUserName', 'data.win.eventdata.user')
    requested = tuple(name for path in ip_paths+account_paths for name in (path,path+'.keyword'))
    caps = client.field_capabilities(requested)
    # A field can be mapped in Windows indexes and absent in Linux indexes.
    # Ignore only unmapped entries; conflicting/unsupported real mappings fail.
    usable = dict(caps) if isinstance(caps, dict) else {}
    usable['fields'] = {name: {kind: info for kind,info in types.items() if kind!='unmapped'}
        for name,types in usable.get('fields',{}).items() if isinstance(types,dict)}
    def mapped(paths, allowed):
        fields=[]
        for path in paths:
            try:
                fields.append(_mapped_field(usable,(path,path+'.keyword'),allowed))
            except ArchiveUnavailable:
                pass
        return fields
    ip_fields = mapped(ip_paths, {'ip','keyword','constant_keyword'})
    user_fields = mapped(account_paths, {'keyword','constant_keyword'})
    if not ip_fields or not user_fields:
        raise ArchiveUnavailable('Network source or account pivot mapping is unavailable.')
    variants = {source_ip, str(address)}
    if address.version == 4:
        variants.update(('::ffff:'+str(address), str(ipaddress.IPv6Address('::ffff:'+str(address)))))
    first, last = group.get('first_seen_utc') or start, group.get('last_seen_utc') or end
    payload = {'size':max_events,'track_total_hits':True,'_source':list(SOURCE_FIELDS),
        'query':{'bool':{'filter':[
            {'range':{time_field:{'gte':start.isoformat(),'lte':end.isoformat()}}},
            {'bool':{'should':[{'terms':{field:sorted(variants)}} for field in ip_fields],
                     'minimum_should_match':1}},
            {'bool':{'should':[{'term':{field:username}} for field in user_fields],
                     'minimum_should_match':1}}],
            'must_not':[{'term':{agent_field:group['agent_id']}}]}},
        'sort':_nearest_sort(time_field,first,last)}
    response = client.search_documents(payload)
    if (not isinstance(response,dict) or response.get('timed_out') is True or
            not isinstance(response.get('hits'),dict) or
            not isinstance(response['hits'].get('hits'),list)):
        raise ArchiveInvalid('Cross-agent archive response is incomplete.')
    shards = response.get('_shards')
    if isinstance(shards,dict) and shards.get('failed',0):
        raise ArchiveInvalid('Cross-agent archive search reported shard failures.')
    hits = response['hits']['hits']
    if len(hits)>max_events:
        raise ArchiveInvalid('Cross-agent archive response exceeded the bounded limit.')
    total = response['hits'].get('total')
    exact = type(total) is int or (isinstance(total,dict) and total.get('relation')=='eq')
    total = total.get('value') if isinstance(total,dict) else total
    if total is not None and (type(total) is not int or total<len(hits)):
        raise ArchiveInvalid('Cross-agent archive total count is invalid.')
    truncated = total is None or total>len(hits) or not exact
    seen, evidence = set(), []
    for hit in hits:
        if not isinstance(hit,dict) or not isinstance(hit.get('_source'),dict):
            raise ArchiveInvalid('Cross-agent archive document is malformed.')
        index,document_id=hit.get('_index'),hit.get('_id')
        if (not isinstance(index,str) or not index.startswith('wazuh-archives-') or
                not isinstance(document_id,str) or not document_id or (index,document_id) in seen):
            raise ArchiveInvalid('Cross-agent archive provenance is invalid or duplicated.')
        seen.add((index,document_id))
        source=hit['_source'];selected=_selected(source)
        matching_account=next((field for field in account_paths
                               if _text(_field(source,field),256)==username),None)
        observed_source = _cross_address(selected.get('source_ip'))
        agent=_text(_field(source,'agent.id'),64)
        observed=event_time(_text(_field(source,time_field),100))
        if (not agent or agent==group['agent_id'] or observed is None or not start<=observed<=end
                or observed_source!=address or matching_account is None):
            raise ArchiveInvalid('Cross-agent document does not verify the observed pivots.')
        selected['username']=username
        selected['username_source_field']=matching_account
        selected['source_ip']=source_ip
        summary=_text(_field(source,'rule.description'),256) or _text(_field(source,'decoder.name'),128)
        evidence.append(dict(source_index=index,source_document_id=document_id,
            event_timestamp=observed.isoformat(),agent_id=agent,
            event_type=_text(_field(source,'decoder.name'),128) or selected.get('event_id'),
            short_summary=summary or 'Related archive event',selected_fields=selected,
            observed_utc=observed))
    evidence.sort(key=lambda item:(item['observed_utc'],item['source_index'],item['source_document_id']))
    return evidence,total,truncated


def _connector(connection):
    rows = connection.execute('''SELECT * FROM siem_connections
        WHERE is_enabled=1 AND connector_type='wazuh_indexer' ORDER BY id''').fetchall()
    return rows[0] if len(rows) == 1 else None


def _ensure_case(group, connection):
    """Open one analyst case per group anchor, preserving historical auto-cases."""
    anchor = group['alert_ids'][0]
    with connection:
        connection.execute('BEGIN IMMEDIATE')
        existing = connection.execute('''SELECT id FROM incidents
            WHERE case_origin='analyst_group' AND group_anchor_alert_id=?''', (anchor,)).fetchone()
        if existing:
            incident_id = existing['id']
        else:
            representative = connection.execute('SELECT id FROM alerts WHERE id=?',
                                                (group['representative_alert_id'],)).fetchone()
            if representative is None:
                raise LookupError('Selected grouped alert is unavailable.')
            incident_id = connection.execute('''INSERT INTO incidents
                (alert_id,asset_id,title,detected_at,last_activity_at,summary,
                 case_origin,group_anchor_alert_id,engine_version)
                VALUES(?,?,?,?,?,?,'analyst_group',?,'group-case-v1')''',
                (group['representative_alert_id'],group['asset_id'],
                 group['rule_description'] or 'Grouped SIEM alert',group['first_seen'],
                 group['last_seen'],'Opened by an analyst from a grouped alert.',anchor)).lastrowid
        for ordinal, alert_id in enumerate(group['alert_ids']):
            connection.execute('''INSERT OR IGNORE INTO investigation_case_alerts
                (case_id,alert_id,ordinal) VALUES(?,?,?)''', (incident_id,alert_id,ordinal))
            linked = connection.execute('''SELECT case_id FROM investigation_case_alerts
                WHERE alert_id=?''',(alert_id,)).fetchone()
            if linked is None or linked['case_id'] != incident_id:
                raise ValueError('Grouped alert membership conflicts with an existing analyst case.')
            attach_alert_context(connection,incident_id,alert_id)
        connection.execute('''UPDATE incidents SET last_activity_at=?,updated_at=CURRENT_TIMESTAMP
            WHERE id=?''',(group['last_seen'],incident_id))
        priority = group['initial_priority']
        connection.execute('''INSERT OR IGNORE INTO initial_alert_priorities
            (incident_id,initial_priority,initial_priority_model_version,
             initial_priority_rationale,factors_json) VALUES(?,?,?,?,?)''',
            (incident_id,priority.level,priority.model_version,priority.rationale,
             json.dumps({'severity_tier':priority.severity_tier,
                         'asset_criticality':priority.asset_criticality,
                         'mitre_modifier':priority.mitre_modifier,
                         'recurrence_modifier':priority.recurrence_modifier,
                         'occurrence_count_used':priority.occurrence_count_used,
                         'group_window_minutes':group['group_window_minutes']},sort_keys=True)))
        return incident_id


def start_group_archive_retrieval(member_alert_id):
    """Create an explicit execution, then query archives without holding a DB lock."""
    connection = get_db_connection()
    try:
        group = group_context(connection, member_alert_id)
        if group is None:
            raise LookupError('Grouped alert not found.')
        incident_id = _ensure_case(group, connection)
        buffer_minutes = _bounded_setting('INVESTIGATION_EVIDENCE_BUFFER_MINUTES',
                                          DEFAULT_BUFFER_MINUTES, 1440)
        max_events = _bounded_setting('INVESTIGATION_MAX_ARCHIVE_EVENTS',
                                      DEFAULT_MAX_EVENTS, 1000)
        start_time = group['first_seen_utc']
        end_time = group['last_seen_utc']
        start = start_time - timedelta(minutes=buffer_minutes) if start_time else None
        end = end_time + timedelta(minutes=buffer_minutes) if end_time else None
        connector = _connector(connection)
        pivots = _group_pivots(connection, group)
        selection = select_playbook(group, pivots)
        with connection:
            execution_id = connection.execute('''INSERT INTO investigations
                (incident_id,playbook_key,status) VALUES(?,?,'running')''',
                (incident_id, ARCHIVE_PLAYBOOK)).lastrowid
            connection.execute('''INSERT INTO investigation_archive_runs (
                investigation_id,connector_id,trigger_alert_id,asset_id,asset_name_snapshot,
                asset_criticality_snapshot,asset_protected_snapshot,reported_agent_id,
                reported_agent_name,rule_id,rule_description,first_seen,last_seen,
                window_start,window_end,group_occurrences,pivots_json,
                selected_playbook_key,selected_playbook_source_hash,
                selection_reason,matched_triggers_json,retrieval_status)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,'running')''',
                (execution_id, connector['id'] if connector else None,
                 group['representative_alert_id'], group['asset_id'], group['asset_name'],
                 group['criticality'], group['is_protected'], group['agent_id'],
                 group['agent_name'], group['rule_id'], group['rule_description'],
                 start_time.isoformat() if start_time else None, end_time.isoformat() if end_time else None,
                 start.isoformat() if start else None, end.isoformat() if end else None,
                 group['occurrences'], json.dumps(pivots, ensure_ascii=True),
                 selection.playbook.key,
                 (imported_playbook(selection.playbook.key) or {}).get('source_sha256'),
                 selection.reason,
                 json.dumps(selection.matched_triggers, ensure_ascii=True)))
            connection.executemany('''INSERT INTO investigation_archive_triggers
                (investigation_id,alert_id) VALUES(?,?)''',
                [(execution_id, alert_id) for alert_id in group['alert_ids']])
    finally:
        connection.close()

    try:
        if not group['agent_id'] or start is None or end is None:
            raise ArchiveUnavailable('Reported agent or event time is unavailable.')
        if connector is None:
            raise ArchiveUnavailable('A single enabled Wazuh connector is unavailable.')
        adapter = create_connector(connector['connector_type'],
            base_url=f"{connector['base_url']}:{connector['port']}",
            username=connector['username'],
            password=unprotect_secret(connector['encrypted_password']),
            index_name=ARCHIVE_INDEX, verify_tls=bool(connector['verify_tls']),
            timeout_seconds=10)
        time_field, agent_field, evidence, total_hits, total_exact, truncated = _query(
            adapter.client, group, start, end, max_events)
        cross_status='unavailable'
        cross_evidence=[]
        cross_total=None
        cross_truncated=None
        try:
            cross_evidence,cross_total,cross_truncated=_query_cross_asset(adapter.client,group,pivots,start,end,
                min(max_events,50),time_field,agent_field)
            cross_status='available' if cross_evidence else 'empty'
        except ArchiveUnavailable:
            cross_status='unavailable'
        except (ArchiveInvalid,WazuhIndexerError):
            cross_status='failed'
        status = 'available' if evidence else 'empty'
        connection = get_db_connection()
        try:
            with connection:
                connection.executemany('''INSERT INTO investigation_archive_evidence
                    (investigation_id,source_index,source_document_id,event_timestamp,
                     agent_id,event_type,short_summary,selected_fields_json)
                    VALUES(?,?,?,?,?,?,?,?)''',
                    [(execution_id, item['source_index'], item['source_document_id'],
                      item['event_timestamp'], item['agent_id'], item['event_type'],
                      item['short_summary'], json.dumps(item['selected_fields'], ensure_ascii=True))
                     for item in evidence+cross_evidence])
                connection.execute('''UPDATE investigation_archive_runs SET
                    timestamp_field=?,agent_field=?,retrieval_status=?,retrieved_count=?,
                    total_hits=?,total_hits_exact=?,truncated=?,cross_retrieval_status=?,
                    cross_retrieved_count=?,cross_total_hits=?,cross_truncated=?,updated_at=CURRENT_TIMESTAMP
                    WHERE investigation_id=?''',
                    (time_field, agent_field, status, len(evidence), total_hits,
                     int(total_exact) if total_exact is not None else None,
                     int(truncated),cross_status,len(cross_evidence),cross_total,
                     int(cross_truncated) if cross_truncated is not None else None,execution_id))
                connection.execute('''UPDATE investigations SET status='completed',
                    completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?''',
                    (execution_id,))
        finally:
            connection.close()
    except Exception as error:
        # Deliberately omit exception text: remote responses can contain secrets.
        category = ('archive_unavailable' if isinstance(
            error, (ArchiveUnavailable, WazuhIndexerError, SecretProtectionError))
            else 'retrieval_failed')
        connection = get_db_connection()
        try:
            with connection:
                connection.execute('''UPDATE investigation_archive_runs SET
                    retrieval_status=?,error_category=?,updated_at=CURRENT_TIMESTAMP
                    WHERE investigation_id=?''',
                    ('unavailable' if category == 'archive_unavailable' else 'failed',
                     category, execution_id))
                connection.execute('''UPDATE investigations SET status='failed',
                    completed_at=CURRENT_TIMESTAMP,updated_at=CURRENT_TIMESTAMP WHERE id=?''',
                    (execution_id,))
        finally:
            connection.close()
    return execution_id


def archive_run_detail(connection, execution_id):
    row = connection.execute('''SELECT r.*,i.incident_id,i.status AS execution_status,
        s.name AS connector_name FROM investigation_archive_runs r
        JOIN investigations i ON i.id=r.investigation_id
        LEFT JOIN siem_connections s ON s.id=r.connector_id
        WHERE r.investigation_id=?''', (execution_id,)).fetchone()
    if row is None:
        return None
    result = dict(row)
    result['playbook'] = (imported_definition(result['selected_playbook_key'])
                          if result['selected_playbook_key'] in PLAYBOOKS else None)
    result['matched_triggers'] = json.loads(result['matched_triggers_json']) if result['matched_triggers_json'] else []
    result['reported_system'] = source_label(result['reported_agent_id'],
                                              result['reported_agent_name'])
    result['pivots'] = json.loads(result['pivots_json'])
    result['trigger_alert_ids'] = [item[0] for item in connection.execute('''
        SELECT alert_id FROM investigation_archive_triggers
        WHERE investigation_id=? ORDER BY alert_id''', (execution_id,))]
    result['evidence'] = []
    for item in connection.execute('''SELECT * FROM investigation_archive_evidence
        WHERE investigation_id=?''',
        (execution_id,)):
        evidence = dict(item)
        evidence['selected_fields'] = json.loads(evidence['selected_fields_json'])
        evidence['related_system'] = evidence['agent_id'] != result['reported_agent_id']
        result['evidence'].append(evidence)
    result['evidence'].sort(key=lambda item: (
        event_time(item['event_timestamp']), item['source_index'], item['source_document_id']))
    return result


def archive_runs_for_case(connection, incident_id):
    return [dict(row) for row in connection.execute('''
        SELECT r.investigation_id,r.retrieval_status,r.retrieved_count,r.truncated,
               r.cross_retrieval_status,r.cross_retrieved_count,r.cross_total_hits,r.cross_truncated,
               r.window_start,r.window_end,r.created_at
        FROM investigation_archive_runs r JOIN investigations i ON i.id=r.investigation_id
        WHERE i.incident_id=? ORDER BY r.investigation_id DESC''', (incident_id,))]
