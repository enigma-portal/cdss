"""Read-only presentation of decisive saved evidence, never a new assessment."""
import json

from app.services.contextual_risk import _file_related, _file_ordered, _file_event_time
from app.services.investigation import _file_events, _outcome, _remote_events
from app.services.archive_evidence import archive_coverage
from app.services.incident_correlation import event_time
from app.services.playbook_registry import AUTH, REMOTE_ACCESS


def evidence_progression(assessment, investigation):
    result = dict(decisive=[], background=[], coverage='unavailable')
    if not assessment or not investigation:
        return result
    try:
        inputs = json.loads(assessment['inputs_snapshot'])
        ids = set(inputs.get('decisive_evidence_ids', inputs.get('decisive_alert_ids', [])))
        findings = {f['finding_key']: json.loads(f['finding_value']) for f in investigation['findings']}
    except (TypeError, ValueError, AttributeError):
        return result
    result['coverage'] = archive_coverage(findings.get('archive_coverage'))
    evidence = {a['id']: a for a in findings.get('linked_alert_evidence', [])}
    events = _file_events(evidence.values())
    file_ids = {event['alert_id'] for event in events}
    remote = ({event['alert_id']: event for event in _remote_events(evidence.values())}
              if investigation.get('playbook_key') == REMOTE_ACCESS else {})
    # Labels come from actual saved source observations. Membership is always
    # the assessment's saved decisive IDs, never a newly computed T-state.
    for alert in evidence.values():
        if alert['id'] in file_ids:
            continue
        outcome = _outcome(alert)
        fields = alert.get('source_fields', {})
        if outcome in ('failure', 'success'):
            events.append(dict(alert_id=alert['id'],
                               kind='remote_authentication' if alert['id'] in remote else 'authentication',
                               outcome=outcome, username=alert.get('username') or fields.get('username'),
                               destination_ip=alert.get('destination_ip') or fields.get('destination_ip')))
        elif alert['id'] in ids:
            events.append(dict(alert_id=alert['id'], kind='detection',
                               description=alert.get('rule_description')))
    process = next((e for e in events if e['kind']=='process' and e['alert_id'] in ids), None)
    for event in events:
        alert = evidence[event['alert_id']]
        fields = alert.get('source_fields', {})
        observed = (_file_event_time(alert) if event['alert_id'] in file_ids
                    else event_time(alert.get('event_timestamp')))
        row = dict(event, timestamp=observed.isoformat() if observed else None,
                   received=alert.get('event_timestamp'), process_id=fields.get('process_id'),
                   process_guid=fields.get('process_guid'), source_ip=alert.get('source_ip') or fields.get('source_ip'),
                   agent_id=alert.get('agent_id'),
                   destination_port=fields.get('destination_port'), relation='No process-instance relationship established.')
        row['label'] = (('Remote authentication ' if event['kind'] == 'remote_authentication'
                         else 'Authentication ') + event['outcome']
                        if event['kind'] in ('authentication', 'remote_authentication')
                        else event.get('description') or event['kind'].title())
        if event['alert_id'] in ids:
            if (investigation.get('playbook_key') in (AUTH, REMOTE_ACCESS) or
                    event['kind'] in ('authentication', 'remote_authentication', 'detection')):
                row['relation'] = 'Decisive observation recorded in the saved assessment; authorization and malicious intent are not established.'
                pairs = findings.get('successful_authentication_after_failures', [])
                if isinstance(pairs, list) and any(
                        isinstance(pair, dict) and event['alert_id'] in (
                            pair.get('before_alert_id'), pair.get('after_alert_id')) for pair in pairs):
                    row['relation'] = 'Part of the failure-to-success sequence recorded in the saved findings; this does not establish compromise.'
            elif event['kind']=='process':
                row['relation'] = 'Process creation observation; reference process instance for this progression.'
            elif process and _file_related(process, event, evidence):
                ordered = (_file_ordered(process,event,evidence) if event['kind']=='file' else
                           _file_event_time(evidence[process['alert_id']]) is not None and
                           _file_event_time(alert) is not None and
                           _file_event_time(alert) > _file_event_time(evidence[process['alert_id']]))
                if ordered:
                    pf = evidence[process['alert_id']].get('source_fields', {})
                    identity = ('matching ProcessGuid on the same agent' if pf.get('process_guid') and fields.get('process_guid')
                                else 'matching PID on the same agent within the bounded time window')
                    row['relation'] = 'Linked to the process by '+identity+'; source-event ordering is coherent.'
                    if event['kind'] == 'network':
                        files=[evidence[e['alert_id']] for e in events if e['kind']=='file' and e['alert_id'] in ids]
                        if files and all(_file_event_time(f) is not None and
                                         _file_event_time(f) < _file_event_time(alert) for f in files):
                            row['relation'] += ' Network activity follows the decisive file observation; file-to-network causation is not established.'
                else:
                    row['relation'] = 'Saved decisive observation has contradictory temporal ordering; re-run investigation.'
            row['relation_summary'] = ('Matching process instance and coherent source-event order.'
                                       if row['relation'].startswith('Linked to the process by ')
                                       else row['relation'])
            result['decisive'].append(row)
        else:
            result['background'].append(row)
    result['decisive'].sort(key=lambda r: (r['timestamp'] or '', r['alert_id']))
    return result
