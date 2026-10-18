"""Deterministic evidence observations only. No scoring, verdicts, or response actions.

Versioned playbooks use exact source groups. Counts are stored alert counts, not
login attempt totals (a Wazuh alert may itself aggregate events). Temporal checks
require timezone-aware timestamps, a shared account/source and no conflicting
known account/source. 'Not observed' means within this evidence snapshot only.
"""
import json
from datetime import datetime, timezone

from app.database import get_db_connection
from app.services.alert_parser import stored_reported_account, stored_reported_source_ip, stored_reported_destination_ip
from app.services.archive_evidence import _selected
from app.services.incident_correlation import event_time
from app.services.mitre_mapping import get_alert_mitre_context
from app.services.playbook_registry import (
    FILE_PROCESS, REMOTE_ACCESS, select_playbook,
)
from app.services.imported_playbooks import check_keys, EXPECTED_CHECKS, imported_playbook

AUTH = 'authentication_review_v1'
FALLBACK = 'generic_evidence_review_v1'
FAILURE = 'authentication_failed'
SUCCESS = 'authentication_success'


def _groups(alert):
    try:
        groups = alert['rule_groups']
        if isinstance(groups, str):
            groups = json.loads(groups or 'null')
    except (ValueError, TypeError):
        return None
    if not isinstance(groups, list) or not groups or any(not isinstance(g, str) for g in groups):
        return None
    return set(groups)


def _outcome(alert):
    groups = _groups(alert)
    if groups is None or {FAILURE, SUCCESS} <= groups:
        return None
    if FAILURE in groups:
        return 'failure'
    if SUCCESS in groups:
        return 'success'
    return 'other'


def _related(left, right):
    """None: entity context unavailable; False: conflicting known identity."""
    shared = False
    for field in ('username', 'source_ip'):
        a, b = left[field], right[field]
        if a and b:
            if a != b:
                return False
            shared = True
    return True if shared else None


def _summary(alert):
    if 'raw_alert' not in alert:
        return {key: alert.get(key) for key in (
            'id', 'wazuh_alert_id', 'event_timestamp', 'rule_id', 'rule_description',
            'rule_level', 'agent_id', 'asset_id', 'source_ip', 'destination_ip',
            'username', 'rule_groups', 'source_fields', 'source_provenance')}
    summary = {key: alert[key] for key in (
        'id', 'wazuh_alert_id', 'event_timestamp', 'rule_id', 'rule_description',
        'rule_level', 'agent_id', 'asset_id', 'source_ip', 'destination_ip', 'username')}
    groups = _groups(alert)
    summary['rule_groups'] = sorted(groups) if groups is not None else None
    try:
        source = json.loads(alert['raw_alert'])
    except (ValueError, TypeError):
        source = None
    summary['source_fields'] = _selected(source) if isinstance(source, dict) else {}
    return summary


def _archive_row_as_alert(row, incident, trigger_agent_id):
    fields = json.loads(row['selected_fields_json'])
    if not isinstance(fields,dict):
        raise ValueError('Archive selected fields must be an object')
    groups = fields.get('rule_groups')
    if not isinstance(groups,list) or not all(isinstance(g,str) for g in groups):
        groups = None
    return dict(id=-row['id'],wazuh_alert_id=fields.get('source_alert_id') or
        f"{row['source_index']}/{row['source_document_id']}",
        event_timestamp=row['event_timestamp'],rule_id=fields.get('rule_id'),
        rule_description=fields.get('rule_description') or row['short_summary'],
        rule_level=fields.get('rule_level'),agent_id=row['agent_id'],
        asset_id=incident['asset_id'] if row['agent_id']==trigger_agent_id else None,
        source_ip=fields.get('source_ip'),destination_ip=fields.get('destination_ip'),
        username=fields.get('username'),rule_groups=groups,source_fields=fields,
        source_provenance={'type':'wazuh_archive','archive_evidence_id':row['id'],
                           'source_index':row['source_index'],
                           'source_document_id':row['source_document_id']})


def _archive_alerts(connection, incident, alerts):
    """Snapshot real records from the latest bounded retrieval for evaluation."""
    run = connection.execute('''SELECT r.investigation_id,r.retrieval_status
        FROM investigation_archive_runs r JOIN investigations i ON i.id=r.investigation_id
        WHERE i.incident_id=? ORDER BY r.investigation_id DESC LIMIT 1''',
        (incident['id'],)).fetchone()
    if not run or run['retrieval_status'] not in ('available','empty') or not alerts:
        return []
    known_source_ids = {a['wazuh_alert_id'] for a in alerts if a['wazuh_alert_id']}
    result = []
    for row in connection.execute('''SELECT * FROM investigation_archive_evidence
        WHERE investigation_id=? ORDER BY id''',(run['investigation_id'],)):
        try:
            alert = _archive_row_as_alert(row,incident,alerts[0]['agent_id'])
        except (ValueError,TypeError):
            continue
        if alert['wazuh_alert_id'] in known_source_ids:
            continue
        result.append(alert)
    return result


def _file_events(alerts):
    """Only exact structured source categories yield file/process observations."""
    result = []
    for alert in alerts:
        groups = _groups(alert) if 'raw_alert' in alert else set(alert.get('rule_groups') or [])
        fields = _summary(alert)['source_fields'] if 'raw_alert' in alert else alert.get('source_fields', {})
        if not isinstance(fields, dict) or groups is None:
            continue
        event_id = fields.get('event_id')
        if ('sysmon_eid11_detections' in groups or
                ('sysmon' in groups and event_id == '11')) and fields.get('file_path') and event_id in (None, '11'):
            kind = 'file'
        elif ('sysmon_eid1_detections' in groups or
              ('sysmon' in groups and event_id == '1')) and fields.get('process_name') and event_id in (None, '1'):
            kind = 'process'
        elif ('sysmon_eid3_detections' in groups or
              ('sysmon' in groups and event_id == '3')) and fields.get('destination_ip') and event_id in (None, '3'):
            kind = 'network'
        elif 'syscheck' in groups and fields.get('file_path'):
            kind = 'integrity'
        else:
            continue
        result.append({'alert_id': alert['id'], 'kind': kind,
                       'file_path': fields.get('file_path'),
                       'process_name': fields.get('process_name'),
                       'command_line': fields.get('command_line'),
                       'destination_ip': fields.get('destination_ip') or alert.get('destination_ip'),
                       'username': fields.get('username') or alert.get('username')})
    return result


def _remote_events(alerts):
    """Remote context needs an observed authentication record, not ATT&CK alone."""
    result = []
    for alert in alerts:
        groups = _groups(alert) if 'raw_alert' in alert else set(alert.get('rule_groups') or [])
        fields = _summary(alert)['source_fields'] if 'raw_alert' in alert else alert.get('source_fields', {})
        if not isinstance(fields, dict) or groups is None:
            continue
        outcome = ('failure' if FAILURE in groups and SUCCESS not in groups else
                   'success' if SUCCESS in groups and FAILURE not in groups else None)
        if fields.get('event_id') in ('4624', '4625', '4771') and outcome != (
                'success' if fields['event_id'] == '4624' else 'failure'):
            continue
        windows = ('windows_security' in groups and
                   ((outcome == 'success' and fields.get('event_id') == '4624') or
                    (outcome == 'failure' and fields.get('event_id') in ('4625', '4771'))))
        ssh = 'sshd' in groups
        if not outcome or not (windows or ssh):
            continue
        source = alert.get('source_ip') or fields.get('source_ip')
        account = alert.get('username') or fields.get('username')
        if not source and not account:
            continue
        result.append({'alert_id': alert['id'], 'outcome': outcome,
                       'source_ip': source, 'username': account,
                       'destination_ip': alert.get('destination_ip') or fields.get('destination_ip'),
                       'agent_id': alert.get('agent_id')})
    return result


def _incident_playbook(connection, alerts):
    groups, mitre_ids, event_ids = set(), set(), set()
    file_paths, processes = [], []
    for alert in alerts:
        groups.update(_groups(alert) or ())
        context = get_alert_mitre_context(connection, alert['id'])
        mitre_ids.update(mapping['technique_id'] for mapping in context['mappings'])
        fields = _summary(alert)['source_fields']
        if fields.get('event_id'):
            event_ids.add(fields['event_id'])
        if fields.get('file_path'):
            file_paths.append(fields['file_path'])
        if fields.get('process_name'):
            processes.append(fields['process_name'])
    return select_playbook({'mitre_ids': sorted(mitre_ids)},
        {'rule_groups': sorted(groups), 'event_id': event_ids,
         'file_path': file_paths, 'process_name': processes}).playbook.key


def _finding(key, kind, value, status, rationale, alerts=()):
    return dict(key=key, kind=kind, value=value, status=status,
                rationale=rationale, evidence=list(dict.fromkeys(a['id'] for a in alerts)))


def _temporal_pairs(before, after):
    pairs, uncertain = [], False
    for left in before:
        for right in after:
            if ((left['agent_id'] and right['agent_id'] and left['agent_id'] != right['agent_id']) or
                    (left['asset_id'] is not None and right['asset_id'] is not None and
                     left['asset_id'] != right['asset_id'])):
                continue
            relation = _related(left, right)
            if relation is False:
                continue
            earlier, later = event_time(left['event_timestamp']), event_time(right['event_timestamp'])
            if earlier is not None and later is not None and later <= earlier:
                continue
            if relation is None or earlier is None or later is None:
                uncertain = True
            else:
                pairs.append({'before_alert_id': left['id'], 'after_alert_id': right['id']})
    return pairs, uncertain


def _auth_findings(alerts):
    failures = [a for a in alerts if _outcome(a) == 'failure']
    successes = [a for a in alerts if _outcome(a) == 'success']
    unknown = any(_outcome(a) is None for a in alerts)
    findings = []
    for key, rows in [('authentication_failures', failures), ('successful_authentication', successes)]:
        findings.append(_finding(key, 'count', {'observed_alert_count': len(rows)},
            'observed' if rows else 'unavailable' if unknown else 'not_observed',
            'Exact authentication source group. Count of linked alerts, not independent login attempts; '
            'rule.firedtimes is not counted. Authentication success does not establish malicious success.', rows))
    sources = {}
    for alert in failures:
        if alert['source_ip']:
            sources.setdefault(alert['source_ip'], []).append(alert['id'])
    repeated = {source: ids for source, ids in sources.items() if len(ids) > 1}
    findings.append(_finding('shared_failure_source', 'observation',
        {'sources': sources, 'repeated_sources': repeated},
        'observed' if repeated else 'unavailable' if unknown or any(not a['source_ip'] for a in failures) else 'not_observed',
        'Two or more actual failure alerts with the same reported source. Missing source is not a negative result.', failures))
    auth = failures + successes
    accounts = list(dict.fromkeys(a['username'] for a in auth if a['username']))
    findings.append(_finding('authentication_accounts', 'context',
        {'accounts': accounts, 'missing_account_alert_count': sum(not a['username'] for a in auth)},
        'observed' if accounts else 'unavailable', 'Reported normalized accounts only; no account inferred.', auth))
    pairs, uncertain = _temporal_pairs(failures, successes)
    pair_ids = {value for pair in pairs for value in pair.values()}
    findings.append(_finding('successful_authentication_after_failures', 'sequence', pairs,
        'observed' if pairs else 'unavailable' if uncertain or unknown else 'not_observed',
        'Strictly later timestamp and shared account/source, with no conflicting known account/source. '
        'This sequence can be legitimate and is not a compromise verdict.',
        [a for a in alerts if a['id'] in pair_ids]))
    # Other correlated detections are exposed verbatim, not classified as attacks.
    others = [a for a in alerts if _outcome(a) == 'other']
    pairs, uncertain = _temporal_pairs(successes, others)
    pair_ids = {value for pair in pairs for value in pair.values()}
    findings.append(_finding('post_authentication_related_detections', 'sequence',
        {'pairs': pairs, 'detections': [_summary(a) for a in others if a['id'] in pair_ids]},
        'observed' if pairs else 'unavailable' if uncertain or unknown else 'not_observed',
        'Later non-authentication detections already linked to this incident, sharing account/source '
        'without conflicting known identity. Rule descriptions are source claims; analyst review is required, '
        'and temporal ordering does not prove causation or malicious progression.',
        [a for a in alerts if a['id'] in pair_ids]))
    return findings


def _build_findings(connection, incident, alerts, playbook):
    if playbook in EXPECTED_CHECKS and check_keys(playbook) != EXPECTED_CHECKS[playbook]:
        raise ValueError('Imported investigation checks are unavailable or incomplete')
    findings = [_finding('linked_alert_evidence', 'evidence', [_summary(a) for a in alerts],
        'observed' if alerts else 'unavailable',
        'Snapshot of all case-linked source alerts. Known timestamps ordered in UTC; '
        'unknown times listed last, never used to infer order.', alerts)]
    asset = connection.execute('SELECT id,asset_name,criticality,is_protected FROM assets WHERE id=?',
                               (incident['asset_id'],)).fetchone()
    findings.append(_finding('asset_context', 'context', dict(asset) if asset else None,
        'observed' if asset else 'unavailable',
        'Administrator-configured incident asset snapshot; criticality is not inferred or used for scoring.'))
    contexts = [{'alert_id': a['id'], **get_alert_mitre_context(connection, a['id'])} for a in alerts]
    mapped = any(c['mappings'] for c in contexts)
    findings.append(_finding('mitre_context', 'context',
        {'status': 'Mapped' if mapped else 'Not Mapped', 'alerts': contexts},
        'observed' if mapped else 'unavailable',
        'Normalized source-aware ATT&CK context only. Not Mapped is valid and does not imply benignness.', alerts))
    if playbook == AUTH:
        findings.extend(_auth_findings(alerts))
    elif playbook == FILE_PROCESS:
        events = _file_events(alerts)
        ids = {event['alert_id'] for event in events}
        findings.append(_finding('file_process_events', 'observation', events,
            'observed' if events else 'unavailable',
            'Exact structured file/process source categories and allowlisted raw fields only; '
            'a detection does not prove execution, malware or progression.',
            [a for a in alerts if a['id'] in ids]))
    elif playbook == REMOTE_ACCESS:
        events = _remote_events(alerts)
        ids = {event['alert_id'] for event in events}
        findings.append(_finding('remote_access_events', 'observation', events,
            'observed' if events else 'unavailable',
            'Observed remote-service authentication context only. An ATT&CK mapping '
            'does not establish a host hop or malicious lateral movement.',
            [a for a in alerts if a['id'] in ids]))
        findings.extend(_auth_findings(alerts))
    else:
        findings.append(_finding('no_specific_playbook', 'context', {'analyst_review_required': True},
            'observed', 'No dedicated structured source context matched. '
            'Generic evidence review only; no automated security conclusion.', alerts))
    if playbook in (AUTH, FILE_PROCESS, REMOTE_ACCESS):
        archive = connection.execute('''SELECT r.investigation_id,r.retrieval_status,r.retrieved_count,r.truncated,
            r.cross_retrieval_status,r.cross_retrieved_count,r.cross_truncated
            FROM investigation_archive_runs r JOIN investigations i ON i.id=r.investigation_id
            WHERE i.incident_id=? ORDER BY r.investigation_id DESC LIMIT 1''',
            (incident['id'],)).fetchone()
        detail = dict(archive) if archive else None
        status = ('observed' if archive and archive['retrieval_status'] == 'available'
                  and archive['retrieved_count'] > 0 and not archive['truncated'] else
                  'not_observed' if archive and archive['retrieval_status'] == 'empty'
                  and not archive['truncated'] else 'unavailable')
        findings.append(_finding('archive_coverage', 'context', detail, status,
            'Only a completed bounded empty search means no archive events were observed '
            'in that window. Missing, failed or truncated retrieval is unavailable; '
            'an empty result does not establish benign activity.'))
        cross_status=('observed' if archive and archive['cross_retrieval_status']=='available'
                      and archive['cross_retrieved_count'] and archive['cross_truncated']==0 else
                      'not_observed' if archive and archive['cross_retrieval_status']=='empty' and archive['cross_truncated']==0
                      else 'unavailable')
        findings.append(_finding('cross_system_coverage','context',detail,cross_status,
            'Other-system activity is linked only by an observed source IP and account '
            'within the bounded window. Missing pivots or failed search are unavailable; '
            'a related log is not a compromise verdict.'))
    return findings


def run_investigation(incident_id):
    """Explicit execution creates history; reads/refreshes never execute checks."""
    connection = get_db_connection()
    execution_id = None
    playbook = 'selection_pending'
    try:
        # One serialized transaction snapshots membership and context atomically.
        # Persist running first so a failed execution remains visible in history.
        with connection:
            if not connection.execute('SELECT 1 FROM incidents WHERE id=?', (incident_id,)).fetchone():
                raise LookupError('Incident not found')
            execution_id = connection.execute('''INSERT INTO investigations(incident_id,playbook_key,status)
                VALUES(?,'selection_pending','running')''', (incident_id,)).lastrowid
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            incident = connection.execute('SELECT * FROM incidents WHERE id=?', (incident_id,)).fetchone()
            if incident is None:
                raise LookupError('Incident not found')
            alerts = [dict(a) for a in connection.execute('''SELECT a.* FROM alerts a
                JOIN case_alert_members ia ON ia.alert_id=a.id WHERE ia.incident_id=?''', (incident_id,))]
            for alert in alerts:
                if not alert['username']:
                    alert['username'] = stored_reported_account(alert['raw_alert'])
                if not alert['source_ip']:
                    alert['source_ip'] = stored_reported_source_ip(alert['raw_alert'])
                if not alert['destination_ip']:
                    alert['destination_ip'] = stored_reported_destination_ip(alert['raw_alert'])
            latest = datetime.max.replace(tzinfo=timezone.utc)
            alerts.sort(key=lambda a: (event_time(a['event_timestamp']) or latest, a['id']))
            playbook = _incident_playbook(connection, alerts)
            evidence = alerts + _archive_alerts(connection, incident, alerts)
            evidence.sort(key=lambda a: (event_time(a['event_timestamp']) or latest, a['id']))
            for finding in _build_findings(connection, incident, evidence, playbook):
                refs = finding['evidence']
                finding_id = connection.execute('''INSERT INTO investigation_findings
                    (investigation_id,finding_key,finding_type,finding_value,finding_status,evidence_alert_id,rationale)
                    VALUES(?,?,?,?,?,?,?)''', (execution_id, finding['key'], finding['kind'],
                    json.dumps(finding['value'], ensure_ascii=True, allow_nan=False), finding['status'],
                    next((alert_id for alert_id in refs if alert_id > 0),None), finding['rationale'])).lastrowid
                connection.executemany('INSERT INTO investigation_finding_alerts(finding_id,alert_id) VALUES(?,?)',
                                       [(finding_id, alert_id) for alert_id in refs if alert_id > 0])
                connection.executemany('''INSERT INTO investigation_finding_archive_evidence
                    (finding_id,archive_evidence_id) VALUES(?,?)''',
                    [(finding_id,-alert_id) for alert_id in refs if alert_id < 0])
            artifact=imported_playbook(playbook)
            connection.execute('''UPDATE investigations SET playbook_key=?,playbook_import_hash=?,
                status='completed',completed_at=CURRENT_TIMESTAMP,
                updated_at=CURRENT_TIMESTAMP WHERE id=?''',
                (playbook,artifact['source_sha256'] if artifact else None,execution_id))
        return execution_id
    except Exception:
        if execution_id is not None:
            with connection:
                connection.execute('''UPDATE investigations SET playbook_key=?,status='failed',completed_at=CURRENT_TIMESTAMP,
                    updated_at=CURRENT_TIMESTAMP WHERE id=?''', (playbook, execution_id))
        raise
    finally:
        connection.close()


def investigation_history(connection, incident_id):
    executions = [dict(row) for row in connection.execute(
        '''SELECT * FROM investigations WHERE incident_id=?
           AND playbook_key<>'wazuh_archive_retrieval_v1' ORDER BY id DESC''', (incident_id,))]
    for execution in executions:
        execution['findings'] = []
        for row in connection.execute('SELECT * FROM investigation_findings WHERE investigation_id=? ORDER BY id',
                                      (execution['id'],)):
            finding = dict(row)
            finding['value_display'] = json.dumps(json.loads(row['finding_value']), ensure_ascii=False, indent=2)
            finding['evidence_ids'] = [r[0] for r in connection.execute(
                'SELECT alert_id FROM investigation_finding_alerts WHERE finding_id=? ORDER BY alert_id', (row['id'],))]
            finding['evidence_ids'].extend(-r[0] for r in connection.execute(
                '''SELECT archive_evidence_id FROM investigation_finding_archive_evidence
                   WHERE finding_id=? ORDER BY archive_evidence_id''',(row['id'],)))
            execution['findings'].append(finding)
    return executions
