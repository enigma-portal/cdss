"""Read-only presentation queries. No assessment or response decisions are made here."""
from collections import Counter
import json
from datetime import datetime, timezone
from math import ceil

from app.database import get_db_connection
from app.time_utils import parse_timestamp
from app.services.alert_parser import stored_reported_account, stored_reported_source_ip, stored_reported_destination_ip
from app.services.incident_correlation import event_time
from app.services.mitre_mapping import get_alert_mitre_context

FILTERS = {
    'severity': ('critical','high','medium','low','unassessed'),
    'status': ('open','investigating','contained','closed'),
    'criticality': ('low','medium','high','critical','unmapped'),
    'evidence': ('T1','T2','T3','T4','Inconclusive'),
    'decision': ('accept','reject','further_investigation_required','pending'),
    'confidence': ('low','medium','high','unavailable'),
    'view': ('actionable','attention','assessed','active','active_high','active_unassessed','further_review'),
}


def incident_rows(connection):
    rows=[dict(r) for r in connection.execute('''
        SELECT i.id,i.title,i.status,i.detected_at,i.last_activity_at,
               a.id AS asset_id,a.asset_name,a.criticality,a.is_protected,
               r.id AS assessment_id,r.risk_level,r.confidence,r.evidence_state,
               r.asset_criticality_snapshot,r.assessed_at,
               d.decision,d.analyst_name_snapshot,d.created_at AS decision_at,
               case_d.decision AS case_decision,
               (SELECT GROUP_CONCAT(t.technique_id, ', ') FROM incident_mitre_techniques t
                 WHERE t.incident_id=i.id) AS mitre_summary,
               (SELECT GROUP_CONCAT(COALESCE(al.rule_id,'') || ' ' || COALESCE(al.agent_name,'') || ' ' ||
                    COALESCE(al.source_ip,'') || ' ' || COALESCE(al.username,''),' ')
                FROM case_alert_members ia JOIN alerts al ON al.id=ia.alert_id WHERE ia.incident_id=i.id) AS search_context
        FROM incidents i LEFT JOIN assets a ON a.id=i.asset_id
        LEFT JOIN risk_assessments r ON r.id=(SELECT MAX(ra.id) FROM risk_assessments ra
            WHERE ra.incident_id=i.id AND ra.assessment_stage='contextual')
        LEFT JOIN analyst_decisions d ON d.id=(SELECT MAX(ad.id) FROM analyst_decisions ad
            WHERE ad.incident_id=i.id AND ad.assessment_id=r.id)
        LEFT JOIN analyst_decisions case_d ON case_d.id=(SELECT MAX(ad.id) FROM analyst_decisions ad
            WHERE ad.incident_id=i.id AND ad.assessment_id=r.id
              AND ad.incident_recommendation_id IS NULL)
        WHERE i.case_origin='analyst_group' OR EXISTS (
            SELECT 1 FROM investigations prior WHERE prior.incident_id=i.id
              AND prior.playbook_key<>'wazuh_archive_retrieval_v1')''')]
    oldest=datetime.min.replace(tzinfo=timezone.utc)
    # Review completion belongs to each current recommendation, not just the
    # most recently recorded decision anywhere on the incident.
    reviews = {}
    for review in connection.execute('''SELECT c.assessment_id,d.decision
        FROM contextual_recommendations c LEFT JOIN analyst_decisions d
        ON d.id=(SELECT MAX(ad.id) FROM analyst_decisions ad
                 WHERE ad.incident_recommendation_id=c.id AND ad.assessment_id=c.assessment_id)'''):
        reviews.setdefault(review['assessment_id'], []).append(review['decision'])
    rows.sort(key=lambda r:(event_time(r['last_activity_at'] or r['detected_at']) or oldest,r['id']),reverse=True)
    for row in rows:
        row['risk_display']=row['risk_level'] or 'Unassessed'
        if row['case_decision']:
            row['decision']=row['case_decision']
            row['pending_recommendations']=0
            row['further_review']=row['case_decision']=='further_investigation_required'
            row['needs_review']=row['status'] in ('open','investigating') and row['further_review']
            continue
        decisions=reviews.get(row['assessment_id'], [])
        row['pending_recommendations']=decisions.count(None)
        row['further_review']='further_investigation_required' in decisions
        row['needs_review']=row['status'] in ('open','investigating') and (
            not decisions or row['pending_recommendations'] > 0 or row['further_review'])
    return rows


def overview_data():
    connection=get_db_connection()
    try:
        rows=incident_rows(connection)
        risk=Counter(r['risk_level'] or 'unassessed' for r in rows)
        confidence=Counter(r['confidence'] or 'unavailable' for r in rows)
        active=[r for r in rows if r['status'] in ('open','investigating')]
        order={risk:index for index,risk in enumerate(FILTERS['severity'])}
        queue=sorted((r for r in rows if r['needs_review']),
                     key=lambda r:order[r['risk_level'] or 'unassessed'])
        from app.services.alert_view import alert_queue_snapshot
        from app.services.asset_resolver import observed_agent_context
        alert_activity = alert_queue_snapshot(connection)
        now = datetime.now(timezone.utc).isoformat()
        ingestion = dict(connection.execute("""SELECT
            SUM(CASE WHEN julianday(created_at) BETWEEN julianday(?,'-15 minutes')
                       AND julianday(?) THEN 1 ELSE 0 END) AS received_recently,
            MAX(created_at) AS latest_ingested_at
            FROM alerts""",(now,now)).fetchone())
        latest_event = connection.execute("""SELECT event_timestamp FROM alerts
            ORDER BY cdss_event_epoch(event_timestamp) DESC,id DESC LIMIT 1""").fetchone()
        alert_activity.update(ingestion)
        alert_activity['received_recently'] = ingestion['received_recently'] or 0
        alert_activity['latest_event_at'] = latest_event[0] if latest_event else None
        endpoints = [source for source in observed_agent_context(connection) if source['agent_id']!='000']
        asset_visibility = dict(observed=len(endpoints),
            mapped=sum(source['asset_id'] is not None for source in endpoints),
            unmapped=sum(source['asset_id'] is None for source in endpoints),
            outside_scope=sum(source['asset_id'] is not None and not source['is_protected'] for source in endpoints))
        return dict(alert_activity=alert_activity,asset_visibility=asset_visibility,total=len(rows),active=sum(r['status'] in ('open','investigating') for r in rows),
            active_high=sum(r['risk_level'] in ('critical','high') for r in active),
            active_unassessed=sum(r['risk_level'] is None for r in active),
            further_review=sum(r['further_review'] for r in active),
            unmapped=sum(r['asset_id'] is None for r in active),
            assessed=sum(r['assessment_id'] is not None for r in rows),
            attention=sum(r['needs_review'] for r in rows),
            risks={key:risk[key] for key in FILTERS['severity']},
            confidences={key:confidence[key] for key in FILTERS['confidence']},
            recent=rows[:8],queue=queue[:8])
    finally:
        connection.close()


def list_data(args):
    connection=get_db_connection()
    try:
        rows=incident_rows(connection)
    finally:
        connection.close()
    filters={key:args.get(key,'') if args.get(key,'') in allowed else '' for key,allowed in FILTERS.items()}
    filters['q']=args.get('q','').strip()[:100]
    total=len(rows)
    totals=dict(total=total,critical=sum(r['risk_level']=='critical' for r in rows),
                high=sum(r['risk_level']=='high' for r in rows),open=sum(r['status']=='open' for r in rows))
    def matches(row):
        q=filters['q'].casefold()
        if q and q not in ' '.join(str(row[k] or '') for k in ('id','title','asset_name','mitre_summary','search_context')).casefold():
            return False
        for key,value in [('severity',row['risk_level'] or 'unassessed'),('status',row['status']),
                ('criticality',row['criticality'] or 'unmapped'),('evidence',row['evidence_state']),
                ('decision',row['decision'] or 'pending'),('confidence',row['confidence'] or 'unavailable')]:
            if filters[key] and filters[key]!=value:
                return False
        return (not filters['view'] or
                (filters['view']=='actionable' and row['risk_level'] in ('high','critical')) or
                (filters['view']=='attention' and row['needs_review']) or
                (filters['view']=='active_high' and row['status'] in ('open','investigating') and row['risk_level'] in ('high','critical')) or
                (filters['view']=='active_unassessed' and row['status'] in ('open','investigating') and row['risk_level'] is None) or
                (filters['view']=='further_review' and row['status'] in ('open','investigating') and row['further_review']) or
                (filters['view']=='active' and row['status'] in ('open','investigating')) or
                (filters['view']=='assessed' and row['assessment_id'] is not None))
    filtered=[r for r in rows if matches(r)]
    pages=max(1,ceil(len(filtered)/20))
    try:
        page=max(1,min(int(args.get('page','1')),pages))
    except (ValueError,TypeError):
        page=1
    pagination=dict(filters,page=page,pages=pages,total=len(filtered),
        page_numbers=list(range(max(1,page-2),min(pages,page+2)+1)),
        active_label=(filters['severity'].title()+' only' if filters['severity'] else
                      'Actionable: High + Critical' if filters['view']=='actionable' else 'Contextual incident triage'))
    return totals,filtered[(page-1)*20:page*20],pagination


def incident_evidence(connection,incident_id):
    rows=[dict(r) for r in connection.execute('''SELECT a.id,a.wazuh_alert_id,a.event_timestamp,
        a.rule_id,a.rule_description,a.rule_level,a.agent_id,a.agent_name,a.agent_ip,
        a.source_ip,a.destination_ip,a.username,a.raw_alert,ia.correlation_reason
        FROM case_alert_members ia JOIN alerts a ON a.id=ia.alert_id WHERE ia.incident_id=?''',(incident_id,))]
    last=datetime.max.replace(tzinfo=timezone.utc)
    rows.sort(key=lambda r:(event_time(r['event_timestamp']) or last,r['id']))
    for row in rows:
        if not row['username']:
            row['username'] = stored_reported_account(row['raw_alert'])
        if not row['source_ip']:
            row['source_ip'] = stored_reported_source_ip(row['raw_alert'])
        if not row['destination_ip']:
            row['destination_ip'] = stored_reported_destination_ip(row['raw_alert'])
        row['time_known']=event_time(row['event_timestamp']) is not None
        row['mitre']=get_alert_mitre_context(connection,row['id'])['mappings']
        row['raw_excerpt']=_safe_source_excerpt(row.pop('raw_alert'))
    return rows


def _safe_source_excerpt(raw):
    """Allowlist source fields for an authenticated audit view; never render arbitrary raw JSON."""
    try:
        source=json.loads(raw)
    except (TypeError,ValueError):
        return None
    if not isinstance(source,dict):
        return None
    if isinstance(source.get('_source'),dict):
        source=source['_source']
    excerpt={key:source[key] for key in ('id','@timestamp','timestamp')
             if isinstance(source.get(key),(str,int))}
    for group,keys in (
        ('rule',('id','description','level','groups')),
        ('agent',('id','name','ip')),
        ('data',('srcip','dstip','user')),
        ('syscheck',('path',)),
    ):
        value=source.get(group)
        if isinstance(value,dict):
            fields={key:value[key] for key in keys if isinstance(value.get(key),(str,int))}
            if group=='rule' and isinstance(value.get('groups'),list) and all(
                    isinstance(item,str) for item in value['groups']):
                fields['groups']=value['groups']
            if group=='rule' and isinstance(value.get('mitre'),dict):
                ids=value['mitre'].get('id')
                if isinstance(ids,list) and all(isinstance(item,str) for item in ids):
                    fields['mitre']={'id':ids}
            if fields:
                excerpt[group]=fields
    data=source.get('data')
    win=data.get('win') if isinstance(data,dict) else None
    if isinstance(win,dict):
        system=win.get('system')
        eventdata=win.get('eventdata')
        selected={}
        if isinstance(system,dict) and isinstance(system.get('eventID'),(str,int)):
            selected['eventID']=system['eventID']
        if isinstance(eventdata,dict):
            selected.update({key:eventdata[key] for key in ('targetUserName','user','ipAddress')
                             if isinstance(eventdata.get(key),(str,int))})
        if selected:
            excerpt.setdefault('data',{}).setdefault('win',{})['reported_fields']=selected
    return json.dumps(excerpt,ensure_ascii=True,indent=2,allow_nan=False) if excerpt else None


def assessment_notices(connection, incident_id, contextual, asset):
    """Explain snapshot freshness without recalculating or replacing any result."""
    if not contextual:
        return []
    notices=[]
    recorded={r[0] for r in connection.execute('''SELECT fa.alert_id
        FROM investigation_finding_alerts fa JOIN investigation_findings f ON f.id=fa.finding_id
        WHERE f.investigation_id=? AND f.finding_key='linked_alert_evidence' ''',
        (contextual['investigation_id'],))}
    current={r[0] for r in connection.execute('SELECT alert_id FROM case_alert_members WHERE incident_id=?',(incident_id,))}
    if recorded != current:
        notices.append('Related alerts have changed since this assessment. The displayed risk still describes the saved investigation, not the new evidence.')
    try:
        inputs=json.loads(contextual['inputs_snapshot'])
        snapshot=inputs.get('asset') if isinstance(inputs,dict) else None
    except (ValueError,TypeError):
        snapshot=None
    snapshot=snapshot if isinstance(snapshot,dict) else {}
    current_asset=dict(asset) if asset else {}
    if any(snapshot.get(key)!=current_asset.get(key) for key in ('id','criticality','is_protected')):
        notices.append('Asset context has changed since the investigation. Current inventory values do not replace the saved criticality snapshot.')
    latest=connection.execute('''SELECT MAX(id) FROM investigations
        WHERE incident_id=? AND playbook_key<>'wazuh_archive_retrieval_v1' ''',
        (incident_id,)).fetchone()[0]
    if latest and latest!=contextual['investigation_id']:
        notices.append('The latest investigation is not the execution used for the displayed assessment. Check execution IDs before reviewing guidance.')
    newer_archive=connection.execute('''SELECT r.retrieval_status FROM investigation_archive_runs r
        JOIN investigations i ON i.id=r.investigation_id
        WHERE i.incident_id=? AND r.investigation_id>? ORDER BY r.investigation_id DESC LIMIT 1''',
        (incident_id,contextual['investigation_id'])).fetchone()
    if newer_archive:
        if newer_archive['retrieval_status'] in ('unavailable','failed'):
            assessed_time = parse_timestamp(contextual['assessed_at'], sqlite_utc=True)
            label = assessed_time.strftime('%Y-%m-%d %H:%M:%S UTC') if assessed_time else 'Time unavailable'
            notices.append('Latest evidence retrieval unavailable. Last successful assessment: '+label+'. Its evidence state and risk remain current.')
        else:
            notices.append('Archive retrieval was attempted after the saved assessment. Its results are not part of the displayed evidence state or risk; re-run the investigation to evaluate them.')
    return notices


FINDING_LABELS = {
    'linked_alert_evidence': 'Linked alert and archive evidence',
    'cross_system_coverage': 'Other-system archive coverage',
    'asset_context': 'Configured asset context',
    'mitre_context': 'MITRE ATT&CK context',
    'no_specific_playbook': 'Generic evidence review',
    'authentication_failures': 'Authentication failure alerts',
    'successful_authentication': 'Successful authentication alerts',
    'shared_failure_source': 'Repeated failures from the same source',
    'authentication_accounts': 'Reported account context',
    'successful_authentication_after_failures': 'Related success after failures',
    'post_authentication_related_detections': 'Later related security detections',
    'file_process_events': 'Structured file and process observations',
    'remote_access_events': 'Remote-service authentication observations',
    'archive_coverage': 'Supporting Wazuh archive logs for this investigation window',
}

CORRELATION_LABELS = {
    'same_asset_source_ip_and_username': 'shared asset, source IP and account',
    'same_asset_and_source_ip': 'shared asset and source IP',
    'same_asset_and_username': 'shared asset and account',
    'same_asset_and_destination_ip': 'shared asset and destination IP',
    'same_asset_and_syscheck_path': 'shared asset and file path',
}

PLAYBOOK_LABELS = {
    'generic_evidence_review_v1': 'Generic Evidence Review',
    'authentication_review_v1': 'Authentication Review',
    'file_process_review_v1': 'Suspicious File / Process Investigation',
    'remote_access_review_v1': 'Remote Access Investigation',
}


def audit_presentation(timeline, techniques, investigations):
    """Concise, read-only audit labels; original records remain in the database."""
    count = len(timeline)
    if count == 0:
        correlation = 'No linked alerts recorded.'
    elif count == 1:
        correlation = 'One linked Wazuh alert; original incident detection.'
    else:
        reasons = list(dict.fromkeys(CORRELATION_LABELS[r['correlation_reason']]
            for r in timeline if r['correlation_reason'] in CORRELATION_LABELS))
        correlation = f'{count} linked Wazuh alerts.'
        if reasons:
            correlation += ' Grouped by ' + '; '.join(reasons[:2]) + '.'
    mapped = []
    for technique in techniques:
        sources = list(dict.fromkeys(
            'Wazuh' if source['mapping_source'] == 'wazuh' else
            'Approved supplementary mapping' if source['mapping_source'] == 'supplementary' else
            'Source unavailable'
            for source in technique['sources']))
        mapped.append({'technique_id':technique['technique_id'],
                       'technique_name':technique['technique_name'],
                       'sources':sources or ['Source unavailable']})
    for run in investigations:
        run['display_method'] = PLAYBOOK_LABELS.get(run['playbook_key'], 'Other investigation method')
        for finding in run['findings']:
            finding['display_label'] = FINDING_LABELS.get(
                finding['finding_key'], finding['finding_key'].replace('_',' ').title())
    return {'correlation':correlation, 'techniques':mapped}


def _assessment_asset(contextual):
    try:
        snapshot = json.loads(contextual['inputs_snapshot']).get('asset')
    except (TypeError, ValueError, AttributeError):
        return None
    return snapshot if isinstance(snapshot, dict) else None


def _observation_labels(finding):
    """Show allowlisted, structured observations rather than a generic finding name."""
    try:
        events = json.loads(finding['finding_value'])
    except (KeyError, TypeError, ValueError):
        return []
    if not isinstance(events, list):
        return []
    labels = []
    for event in events[:3]:
        if not isinstance(event, dict):
            continue
        if finding['finding_key'] == 'file_process_events':
            kind = event.get('kind')
            field = {'file': 'file_path', 'integrity': 'file_path',
                     'process': 'process_name', 'network': 'destination_ip'}.get(kind)
            value = event.get(field) if field else None
            if isinstance(value, str) and value:
                name = {'file': 'File alert', 'integrity': 'Integrity alert',
                        'process': 'Process alert', 'network': 'Network alert'}[kind]
                labels.append(f'{name}: {value}')
        elif finding['finding_key'] == 'remote_access_events':
            outcome = event.get('outcome')
            if outcome not in ('failure', 'success'):
                continue
            parts = [f'Remote authentication {outcome} reported']
            for field, name in (('agent_id', 'on agent'), ('source_ip', 'from'),
                                ('username', 'for account')):
                value = event.get(field)
                if isinstance(value, str) and value:
                    parts.append(f'{name} {value}')
            labels.append(' '.join(parts))
    if len(events) > 3 and labels:
        labels.append(f'{len(events) - 3} more structured observations are in Technical / Audit Details.')
    return labels


def _structured_event_count(investigation, key):
    if not investigation:
        return None
    for finding in investigation.get('findings', ()):
        if finding['finding_key'] != key or finding['finding_status'] != 'observed':
            continue
        try:
            value = json.loads(finding['finding_value'])
        except (KeyError, TypeError, ValueError):
            return None
        return len(value) if isinstance(value, list) else None
    return None


def incident_presentation(incident, asset, timeline, investigations, contextual, notices):
    """Human-readable, read-only view of stored evidence; never reassess an incident."""
    description = incident.get('rule_description') or incident.get('title') or 'a security event'
    location = f" on {asset['asset_name']}" if asset and asset.get('asset_name') else ''
    summary = f'Wazuh reported: {description}{location}.'
    latest = (next((run for run in investigations
                    if run['id'] == contextual['investigation_id']), None)
              if contextual else investigations[0] if investigations else None)
    if latest and latest['playbook_key'] == 'generic_evidence_review_v1':
        summary += ' No dedicated playbook matched; available evidence was reviewed generically.'
    if contextual and contextual['evidence_state'] == 'Inconclusive':
        summary += ' The saved evidence does not support a contextual risk determination.'

    evidence = []
    has_specific_observation = bool(latest and any(
        finding['finding_status'] == 'observed' and
        finding['finding_key'] in ('file_process_events', 'remote_access_events')
        for finding in latest['findings']))
    if timeline and not has_specific_observation:
        evidence.append({'status': 'observed', 'label': f"Wazuh detected: {timeline[0]['rule_description'] or description}"})
    elif not timeline:
        evidence.append({'status': 'unavailable', 'label': 'Linked Wazuh alert evidence is unavailable.'})
    # Use the evidence actually evaluated, including retained archive events.
    evaluated = timeline
    if latest:
        for finding in latest.get('findings', ()):
            if finding['finding_key'] == 'linked_alert_evidence':
                try:
                    snapshot = json.loads(finding['finding_value'])
                except (TypeError, ValueError):
                    snapshot = None
                if isinstance(snapshot, list) and all(isinstance(item, dict) for item in snapshot):
                    evaluated = snapshot
                break
    for field, label in (('source_ip', 'Network Source IP'),
                         ('destination_ip', 'Network Destination IP'), ('username', 'Reported account')):
        values = list(dict.fromkeys(item.get(field) for item in evaluated if item.get(field)))
        evidence.append({'status': 'observed' if values else 'unavailable',
            'label': label + ': ' + ', '.join(values[:3]) if values else
                     label + ' was not present in the evaluated evidence.'})
    if latest:
        if latest['playbook_key'] != 'generic_evidence_review_v1':
            for finding in latest['findings']:
                if finding['finding_key'] in ('linked_alert_evidence', 'asset_context',
                                               'mitre_context', 'no_specific_playbook',
                                               'authentication_accounts'):
                    continue
                if finding['finding_status'] == 'observed' and finding['finding_key'] in (
                        'file_process_events', 'remote_access_events'):
                    specific = _observation_labels(finding)
                    if specific:
                        evidence.extend({'status': 'observed', 'label': text} for text in specific)
                        continue
                if finding['finding_key'] in ('archive_coverage', 'cross_system_coverage'):
                    try:
                        coverage = json.loads(finding['finding_value'])
                    except (TypeError, ValueError):
                        coverage = {}
                    flag = 'cross_truncated' if finding['finding_key']=='cross_system_coverage' else 'truncated'
                    if isinstance(coverage, dict) and coverage.get(flag):
                        name = 'Other-system' if flag=='cross_truncated' else 'Same-asset'
                        evidence.append({'status': 'unavailable', 'label':
                            name + ' archive coverage is partial. Retained events were evaluated; missing activity cannot be ruled out.'})
                        continue
                if finding['finding_key'] == 'archive_coverage':
                    label = {
                        'observed': 'Supporting Wazuh archive logs were retrieved for this investigation window.',
                        'not_observed': 'The completed archive query found zero matching events in this investigation window.',
                        'unavailable': 'Supporting Wazuh archive logs were unavailable for this investigation window.',
                    }.get(finding['finding_status'])
                    if label:
                        evidence.append({'status': finding['finding_status'], 'label': label})
                    continue
                if finding['finding_key'] in ('authentication_failures','successful_authentication'):
                    try:
                        count = json.loads(finding['finding_value']).get('observed_alert_count')
                    except (TypeError, ValueError, AttributeError):
                        count = None
                    if type(count) is int and count >= 0:
                        kind = 'failure' if finding['finding_key']=='authentication_failures' else 'success'
                        evidence.append({'status':finding['finding_status'],
                            'label':f'{count} linked Wazuh authentication {kind} alert(s) in this evidence snapshot.'})
                        continue
                if finding['finding_key'] == 'shared_failure_source' and finding['finding_status']=='observed':
                    try:
                        repeated = json.loads(finding['finding_value']).get('repeated_sources',{})
                    except (TypeError, ValueError, AttributeError):
                        repeated = {}
                    if isinstance(repeated,dict) and repeated:
                        source, ids = next(iter(repeated.items()))
                        if isinstance(ids,list):
                            evidence.append({'status':'observed','label':
                                f'{len(ids)} separate failure alerts report source {source}.'})
                            continue
                label = FINDING_LABELS.get(finding['finding_key'])
                if label:
                    evidence.append({'status': finding['finding_status'], 'label': label})

    why = None
    evidence_reason = None
    decisive_alerts = []
    unavailable_findings = []
    not_observed_findings = []
    if contextual:
        state = contextual['evidence_state'] or 'Inconclusive'
        criticality = contextual['asset_criticality_snapshot']
        risk = contextual['risk_level']
        if state == 'Inconclusive':
            why = 'The saved investigation did not establish a defensible T1–T4 activity state.'
        else:
            why = f'The saved investigation supports {state} evidence.'
        if risk and criticality:
            why += f' With {criticality} asset criticality in that assessment, CDSS assigned {risk} contextual risk.'
        elif (saved_asset := _assessment_asset(contextual)) and not saved_asset.get('is_protected'):
            why += ' Contextual Risk: Unassessed. Asset is not included in contextual assessment scope.'
        elif criticality is None:
            why += ' Unassessed because no mapped asset/criticality/assessment scope is available in the saved assessment.'
        else:
            why += ' No contextual risk was assigned from the saved assessment context.'
        try:
            inputs = json.loads(contextual['inputs_snapshot'])
        except (TypeError, ValueError):
            inputs = {}
        if isinstance(inputs, dict):
            evidence_reason = inputs.get('evidence_reason') if isinstance(inputs.get('evidence_reason'), str) else None
            if evidence_reason == 'One file/process observation is traceable, without related corroboration.':
                count = _structured_event_count(latest, 'file_process_events')
                if count:
                    noun = 'observation' if count == 1 else 'observations'
                    verb = 'is' if count == 1 else 'are'
                    evidence_reason = (f'{count} structured file/process {noun} {verb} traceable, '
                                       'but no related file-and-process corroboration is available.')
            ids = inputs.get('decisive_alert_ids')
            if isinstance(ids, list):
                decisive_alerts = [item for item in timeline if item['id'] in ids]
            for source_key, target in (('unavailable_findings', unavailable_findings),
                                       ('not_observed_findings', not_observed_findings)):
                keys = inputs.get(source_key)
                if isinstance(keys, list):
                    target.extend(FINDING_LABELS[key] for key in keys if key in FINDING_LABELS)
    return {
        'summary': summary,
        'evidence': evidence,
        'why': why,
        'evidence_reason': evidence_reason,
        'decisive_alerts': decisive_alerts,
        'unavailable_findings': unavailable_findings,
        'not_observed_findings': not_observed_findings,
        'playbook_name': PLAYBOOK_LABELS.get(latest['playbook_key'], 'Investigation method') if latest else 'Not run yet',
        'latest_investigation': latest,
        'asset_changed': any(note.startswith('Asset context has changed') for note in notices),
        'other_changes': [note for note in notices if not note.startswith('Asset context has changed')],
    }


def recommendation_presentation(recommendation, asset, timeline, assessment, investigation):
    """Clarify existing guidance for display without selecting or changing a recommendation."""
    evidence_label = None
    artifact = None
    try:
        snapshot = json.loads(recommendation.get('evidence_snapshot') or '{}')
        referenced = set(snapshot.get('alert_ids', ()))
        referenced.update(-identifier for identifier in snapshot.get('archive_evidence_ids', ())
                          if type(identifier) is int and identifier > 0)
    except (TypeError, ValueError, AttributeError):
        referenced = set()
    if investigation and referenced:
        for finding in investigation.get('findings', ()):
            if (finding['finding_key'] == 'file_process_events' and
                    finding['finding_status'] == 'observed'):
                try:
                    events = json.loads(finding['finding_value'])
                except (TypeError, ValueError):
                    events = []
                if isinstance(events, list):
                    for event in events:
                        if isinstance(event, dict) and event.get('alert_id') in referenced:
                            key = {'file': 'file_path', 'integrity': 'file_path',
                                   'process': 'process_name', 'network': 'destination_ip'}.get(event.get('kind'))
                            value = event.get(key) if key else None
                            if isinstance(value, str) and value:
                                artifact = value
                                evidence_label = f'Wazuh {event.get("kind")} observation: {value}'
                                break
            if evidence_label:
                break
        if not evidence_label:
            for finding in investigation.get('findings', ()):
                if finding['finding_key'] != 'linked_alert_evidence':
                    continue
                try:
                    summaries = json.loads(finding['finding_value'])
                except (TypeError, ValueError):
                    summaries = []
                if isinstance(summaries, list):
                    source = next((item for item in summaries if isinstance(item, dict)
                                   and item.get('id') in referenced), None)
                    if source:
                        evidence_label = ('Wazuh '+('archive event' if source['id'] < 0 else 'alert')+
                            ' '+str(source.get('wazuh_alert_id') or '#'+str(source['id']))+
                            ': '+str(source.get('rule_description') or 'description not reported'))
                break
    if not evidence_label:
        source = next((alert for alert in timeline if alert['id'] in referenced), None)
        if source:
            evidence_label = ('Wazuh alert '+(source['wazuh_alert_id'] or '#'+str(source['id']))+
                              ': '+(source['rule_description'] or 'description not reported'))
            if source.get('source_ip'):
                evidence_label += ' · source '+source['source_ip']
            if source.get('username'):
                evidence_label += ' · account '+source['username']
    if recommendation['methodology_version'] == 'cdss-guidance-v2':
        rationale = recommendation['rationale']
        if (recommendation['rule_key'] == 'review_file_origin' and
                rationale == 'One structured file/process observation is recorded.'):
            count = _structured_event_count(investigation, 'file_process_events')
            if count:
                noun = 'observation' if count == 1 else 'observations'
                verb = 'is' if count == 1 else 'are'
                rationale = (f'{count} structured file/process {noun} {verb} recorded '
                             'without related file-and-process corroboration.')
        action = recommendation['action_text']
        if artifact and recommendation['rule_key'] in ('review_file_origin', 'review_lineage'):
            action = (f'Review the origin and execution context of {artifact}; '
                      'verify its parent process, command line and expected use before responding.')
        return {'display_action': action,
                'display_why': rationale, 'display_evidence': evidence_label}
    key = recommendation['rule_key']
    action = recommendation['action_text']
    has_source = any(alert.get('source_ip') for alert in timeline)
    has_account = any(alert.get('username') for alert in timeline)
    if key == 'review_evidence':
        if not timeline:
            why = 'No linked alert is available; verify the underlying detection before responding.'
        elif not has_source and not has_account:
            why = 'The linked alerts lack source and account context, so the available evidence needs validation.'
        elif not has_source or not has_account:
            why = 'The linked alerts lack some source or account context, so the available evidence needs validation.'
        else:
            why = 'Reported source and account details need validation against the linked alert evidence.'
    elif key == 'obtain_context':
        if asset is None:
            action = 'Identify the affected asset and obtain missing evidence, then re-run investigation and assessment.'
            why = 'No configured asset is linked, so business criticality is missing from this assessment.'
        elif not asset['is_protected']:
            action = ('Confirm whether this asset should be included in CDSS protected scope. '
                      'If its configuration changes, re-run investigation and reassess.')
            why = 'The mapped asset is currently outside CDSS protected scope, so its criticality cannot determine contextual risk.'
        elif assessment and not assessment['asset_criticality_snapshot']:
            action = 'Confirm current asset context and obtain missing evidence, then re-run investigation and assessment.'
            why = 'The saved investigation lacks the protected-asset context now available in inventory.'
        else:
            action = 'Obtain missing or contradictory evidence, then re-run investigation and assessment.'
            why = 'The saved investigation did not establish enough consistent evidence for a contextual decision.'
    elif key == 'review_authentication':
        why = 'Linked findings contain authentication failures whose account and source context needs validation.'
    elif key == 'review_account':
        why = 'Account identifiers were reported in linked authentication evidence; their expected access needs validation.'
    elif key == 'validate_success':
        why = 'A successful authentication was observed, but the available evidence does not establish whether it was authorized.'
    elif key == 'review_related_activity':
        why = 'Stored findings link a later successful authentication to failures, but authorization is not established.'
    elif key == 'review_post_activity':
        why = 'Later related security detections are recorded after authentication and need validation.'
    elif key == 'consider_containment':
        why = 'Supported later security detections justify considering containment only if unauthorized activity is confirmed.'
    elif key == 'review_permissions':
        why = 'Related post-authentication detections warrant a review of effective account permissions.'
    elif key == 'repair_confirmed_changes':
        why = 'An integrity-change alert is recorded; restoration applies only if the change is confirmed unauthorized.'
    elif key == 'generic_review':
        why = 'No dedicated playbook matched these alerts, so their meaning requires analyst validation.'
    elif key == 'monitor':
        if investigation and investigation['playbook_key'] == 'generic_evidence_review_v1':
            why = 'Generic findings do not support a specific containment or remediation action; watch for new related evidence.'
        else:
            why = 'Additional related activity may clarify the recorded findings while they are being reviewed.'
    else:
        # Unknown future guidance retains its stored text rather than receiving a guessed reason.
        why = recommendation['rationale']
    return {'display_action': action, 'display_why': why,
            'display_evidence': evidence_label}
