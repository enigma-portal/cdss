"""CDSS qualitative methodology v1: findings -> state -> asset matrix.

No numeric severity, firedtimes, ATT&CK weight/count, or TI input affects final risk.
Explicit conservative rules: two distinct, entity-related failure observations
support T2; two failures linked to the SAME later success support T3; an observed
later security-category detection tied to THAT success supports T4. None confirms
compromise. Unrecognized fallback detections remain Inconclusive.
"""
import json
from app.services.evidence_context import windows_path_equal, is_loopback, is_sysmon
from itertools import combinations

from app.database import get_db_connection
from app.services.alert_parser import stored_reported_account, stored_reported_source_ip, stored_reported_destination_ip
from app.services.incident_correlation import event_time
from app.services.investigation import (
    AUTH, FALLBACK, _file_events, _remote_events, _related, _summary,
)
from app.services.playbook_registry import FILE_PROCESS, REMOTE_ACCESS

VERSION = 'cdss-contextual-v3'
CRITICALITIES = ('low', 'medium', 'high', 'critical')
MATRIX = {
    'T1': dict(zip(CRITICALITIES, ('low','low','medium','medium'))),
    'T2': dict(zip(CRITICALITIES, ('low','medium','high','high'))),
    'T3': dict(zip(CRITICALITIES, ('medium','high','high','critical'))),
    'T4': dict(zip(CRITICALITIES, ('medium','high','critical','critical'))),
}
LABELS = {'T1':'Limited Evidence','T2':'Suspicious Activity','T3':'Strong Evidence',
          'T4':'Advanced / Progressed Activity','Inconclusive':'Inconclusive'}
# Exact existing structured categories only. No description/keyword/MITRE guessing.
# syscheck means a security-relevant integrity detection, NOT proven malicious change.
SECURITY_GROUPS = frozenset(('syscheck', 'malware', 'rootcheck'))


def matrix_risk(state, criticality, protected):
    return MATRIX.get(state, {}).get(criticality) if protected else None


def _security(alert):
    groups = alert.get('rule_groups')
    return isinstance(groups, list) and bool(SECURITY_GROUPS.intersection(groups))


def _same_context(left, right):
    same_asset = ((left.get('asset_id') is not None and left.get('asset_id') == right.get('asset_id'))
                  or (left.get('agent_id') and left.get('agent_id') == right.get('agent_id')))
    return bool(same_asset and _related(left, right) is True)


def _distinct(ids, evidence, category):
    """Collapse duplicate representations; different rules alone are not new evidence."""
    seen, result = set(), []
    for aid in sorted(ids):
        alert = evidence[aid]
        timestamp = event_time(alert.get('event_timestamp'))
        fingerprint = (timestamp or alert.get('event_timestamp'), alert.get('agent_id'),
                       alert.get('asset_id'), alert.get('source_ip'), alert.get('destination_ip'),
                       alert.get('username'), category)
        if fingerprint not in seen:
            seen.add(fingerprint)
            result.append(aid)
    return result


def _pairs(finding, evidence, before_ids, after_ids, key=None):
    value = finding['value'].get(key, []) if key else finding['value']
    if finding['status'] != 'observed':
        return []
    if not isinstance(value, list):
        raise ValueError('Invalid sequence finding')
    if not value:
        raise ValueError('Observed sequence has no supporting pairs')
    valid = []
    for pair in value:
        a, b = pair['before_alert_id'], pair['after_alert_id']
        if a not in before_ids or b not in after_ids or not {a,b} <= finding['refs']:
            raise ValueError('Sequence lacks traceable contributing evidence')
        left, right = evidence[a], evidence[b]
        t1, t2 = event_time(left.get('event_timestamp')), event_time(right.get('event_timestamp'))
        if t1 is None or t2 is None or t2 <= t1 or not _same_context(left,right):
            raise ValueError('Sequence has contradictory temporal/entity evidence')
        valid.append((a,b))
    return valid


def _verified_events(findings, key, evidence, builder):
    finding = findings[key]
    expected = builder(evidence.values())
    actual = finding['value']
    ids = {item['alert_id'] for item in expected}
    if not isinstance(actual, list) or actual != expected or finding['refs'] != ids:
        raise ValueError('Playbook observations are not traceable to the source snapshot')
    if finding['status'] != ('observed' if expected else 'unavailable'):
        raise ValueError('Playbook observation status contradicts the source snapshot')
    return expected


def _file_related(left, right, evidence):
    a, b = evidence[left['alert_id']], evidence[right['alert_id']]
    same_agent = a.get('agent_id') and a.get('agent_id') == b.get('agent_id')
    if not same_agent:
        return False
    for field in ('username',):
        if left.get(field) and right.get(field) and left[field] != right[field]:
            return False
    left_source = a.get('source_ip') or a.get('source_fields', {}).get('source_ip')
    right_source = b.get('source_ip') or b.get('source_fields', {}).get('source_ip')
    if left_source and right_source and left_source != right_source:
        return False
    fa, fb = a.get('source_fields', {}), b.get('source_fields', {})
    ga, gb = fa.get('process_guid'), fb.get('process_guid')
    pa, pb = fa.get('process_id'), fb.get('process_id')
    if ga and gb and ga.casefold() != gb.casefold():
        return False
    if pa and pb and pa != pb:
        return False
    if (left.get('process_name') and right.get('process_name') and
            not windows_path_equal(left['process_name'], right['process_name'])):
        return False
    if ga and gb:
        return True
    # PID reuse cannot identify an unbounded process instance. Use the existing
    # same-asset archive window (10 minutes on either side) as the upper bound.
    from app.services.archive_evidence import DEFAULT_BUFFER_MINUTES
    ta, tb = _file_event_time(a), _file_event_time(b)
    return bool(pa and pb and pa == pb and ta and tb and
                abs((tb-ta).total_seconds()) <= 2 * DEFAULT_BUFFER_MINUTES * 60)


def _file_event_time(alert):
    """Prefer Sysmon's explicit UTC occurrence time over Wazuh receipt time."""
    fields = alert.get('source_fields', {})
    if is_sysmon(fields) and fields.get('utc_time'):
        from app.time_utils import parse_timestamp
        # Sysmon names this field utcTime; do not apply naive-time handling to
        # generic source timestamps or rewrite any retained source strings.
        parsed = parse_timestamp(fields['utc_time'], sqlite_utc=True)
        if parsed is not None:
            return parsed
    return event_time(alert.get('event_timestamp'))


def _file_state(findings, evidence):
    events = _verified_events(findings, 'file_process_events', evidence, _file_events)
    primary = [item for item in events if item['kind'] in ('file', 'process')]
    if not primary:
        return 'Inconclusive', [], 'No traceable structured file/process observation supports this playbook.'
    linked = [(a, b) for a, b in combinations(primary, 2)
              if a['kind'] != b['kind'] and _file_related(a, b, evidence)
              and _file_ordered(a, b, evidence)]
    if not linked:
        noun = 'observation' if len(primary) == 1 else 'observations'
        verb = 'is' if len(primary) == 1 else 'are'
        return 'T1', [primary[0]['alert_id']], (
            f'{len(primary)} structured file/process {noun} {verb} traceable, '
            'but no related file-and-process corroboration is available.')
    def progression(pair):
        file_item, process_item = pair
        core_time = _file_event_time(evidence[file_item['alert_id']])
        candidates = [item for item in events if item['kind'] in ('network', 'integrity')
                and core_time is not None
                and _file_event_time(evidence[item['alert_id']]) is not None
                and _file_event_time(evidence[item['alert_id']]) > core_time
                and _file_related(process_item, item, evidence)]
        return sorted(candidates, key=lambda item: (
            not bool(evidence[process_item['alert_id']].get('source_fields', {}).get('process_guid')
                     and evidence[item['alert_id']].get('source_fields', {}).get('process_guid')),
            _file_event_time(evidence[item['alert_id']]), item['alert_id']))

    def shared_identity(file_item, process_item):
        return (bool(file_item.get('username') and
                     file_item['username'] == process_item.get('username')) or
                bool(evidence[file_item['alert_id']].get('source_ip') and
                     evidence[file_item['alert_id']].get('source_ip') ==
                     evidence[process_item['alert_id']].get('source_ip')))

    file_item, process_item = sorted(
        ((a, b) if a['kind'] == 'file' else (b, a) for a, b in linked),
        key=lambda pair: (not bool(pair[1].get('command_line') and shared_identity(*pair)),
                          not bool(progression(pair)),
                          not bool(evidence[pair[0]['alert_id']].get('source_fields', {}).get('process_guid')
                                   and evidence[pair[1]['alert_id']].get('source_fields', {}).get('process_guid')),
                          not any(item['alert_id'] > 0 for item in pair),
                          pair[0]['alert_id'], pair[1]['alert_id']))[0]
    decisive = {file_item['alert_id'], process_item['alert_id']}
    if not process_item.get('command_line') or not shared_identity(file_item, process_item):
        return 'T2', sorted(decisive), 'Related file and process observations share a reported process or artifact; execution outcome is not established.'
    progressed = progression((file_item, process_item))
    if progressed:
        later = progressed[0]
        return 'T4', sorted(decisive | {later['alert_id']}), (
            'Related file and process observations with a reported command line were followed '
            f'by a linked {later["kind"]} detection. Malicious execution is not confirmed.')
    return 'T3', sorted(decisive), (
        'Related file creation and process observations include a reported command line; '
        'the activity requires analyst validation, not a malware verdict.')


def _file_ordered(left, right, evidence):
    process, file = (left, right) if left['kind'] == 'process' else (right, left)
    start = _file_event_time(evidence[process['alert_id']])
    end = _file_event_time(evidence[file['alert_id']])
    return bool(start is not None and end is not None and start <= end)


def _remote_state(findings, evidence):
    if any({'authentication_failed', 'authentication_success'} <=
           set(alert.get('rule_groups') or []) for alert in evidence.values()):
        return 'Inconclusive', [], 'Contradictory remote authentication outcome categories are present.'
    events = _verified_events(findings, 'remote_access_events', evidence, _remote_events)
    if not events:
        return 'Inconclusive', [], 'No traceable remote-service authentication observation supports this playbook; ATT&CK context alone is insufficient.'
    remote_ids = {item['alert_id'] for item in events}
    failures = _distinct([item['alert_id'] for item in events if item['outcome'] == 'failure'], evidence, 'remote_failure')
    successes = {item['alert_id'] for item in events if item['outcome'] == 'success'}
    repeated = [(a, b) for a, b in combinations(failures, 2) if _same_context(evidence[a], evidence[b])]
    pairs = _pairs(findings['successful_authentication_after_failures'], evidence,
                   findings['authentication_failures']['refs'],
                   findings['successful_authentication']['refs'])
    outcomes = [s for s in successes if any({a, b} <= {x for x, y in pairs if y == s}
                for a, b in repeated)]
    if outcomes:
        success_id = min(outcomes)
        success_event = next(item for item in events if item['alert_id'] == success_id)
        decisive = {a for a, b in pairs if b == success_id and a in failures} | {success_id}
        after = event_time(evidence[success_id].get('event_timestamp'))
        cross_host = [item for item in events if item['outcome'] == 'success'
            and item['alert_id'] != success_id and item['agent_id']
            and item['agent_id'] != evidence[success_id].get('agent_id')
            and item['source_ip'] and not is_loopback(item['source_ip'])
            and item['source_ip'] == success_event['source_ip']
            and item['username'] and item['username'] == success_event['username']
            and after is not None
            and (event_time(evidence[item['alert_id']].get('event_timestamp')) or after) > after]
        if cross_host:
            return 'T4', sorted(decisive | {cross_host[0]['alert_id']}), (
                'Related remote authentication failures and a later success were followed by '
                'an observed remote authentication on a different reported agent with the same source and account. '
                'This is not a malicious lateral-movement verdict.')
        post = findings['post_authentication_related_detections']
        later_ids = {a['id'] for a in post['value'].get('detections', [])}
        later = _pairs(post, evidence, findings['successful_authentication']['refs'], later_ids, 'pairs')
        progression = [(a, b) for a, b in later if a == success_id and _security(evidence[b])]
        if progression:
            return 'T4', sorted(decisive | {progression[0][1]}), (
                'Related remote authentication failures and a later success were followed by '
                'a linked security-category detection; its meaning requires analyst review.')
        return 'T3', sorted(decisive), (
            'Related remote authentication failures preceded the same observed successful logon; '
            'authorization and compromise are not established.')
    if repeated:
        return 'T2', sorted({i for pair in repeated for i in pair}), (
            'Separate related remote authentication failures share reported source/account context.')
    linked = [(a, b) for a, b in pairs if a in remote_ids and b in remote_ids]
    if linked:
        return 'T2', sorted(set(linked[0])), (
            'A remote authentication failure was followed by a related success, without '
            'enough corroboration for a strong-evidence conclusion.')
    return 'T1', [events[0]['alert_id']], (
        'One remote authentication observation is traceable; neither malicious access '
        'nor cross-host progression is established.')


def _state(playbook, findings, evidence):
    if not evidence:
        return 'Inconclusive', [], 'No traceable linked evidence is available.'
    if playbook == FALLBACK:
        return 'Inconclusive', [], 'Generic evidence review does not interpret this activity as a defensible T1–T4 state.'
    if playbook == FILE_PROCESS:
        return _file_state(findings, evidence)
    if playbook == REMOTE_ACCESS:
        return _remote_state(findings, evidence)
    if playbook != AUTH:
        return 'Inconclusive', [], 'Unsupported investigation playbook version.'
    for alert in evidence.values():
        if {'authentication_failed','authentication_success'} <= set(alert.get('rule_groups') or []):
            return 'Inconclusive', [], 'Contradictory authentication outcome categories are present.'
    failures = findings['authentication_failures']
    success = findings['successful_authentication']
    for finding in (failures,success):
        if finding['value'].get('observed_alert_count') != len(finding['refs']):
            raise ValueError('Authentication finding count does not match evidence references')
        if bool(finding['refs']) != (finding['status'] == 'observed'):
            raise ValueError('Authentication finding status contradicts evidence')
    failed_ids = _distinct(failures['refs'], evidence, 'failure')
    if not failed_ids:
        return 'Inconclusive', [], 'Successful authentication alone is not suspicious evidence.'
    repeated = [(a,b) for a,b in combinations(failed_ids,2) if _same_context(evidence[a],evidence[b])]
    if not repeated:
        return 'T1', [failed_ids[0]], 'An isolated authentication failure has no established related repetition.'
    decisive = sorted({i for pair in repeated for i in pair})
    pairs = _pairs(findings['successful_authentication_after_failures'], evidence,
                   failures['refs'], success['refs'])
    outcomes = []
    for sid in success['refs']:
        preceding = {a for a,b in pairs if b == sid}
        if any(a in preceding and b in preceding for a,b in repeated):
            outcomes.append(sid)
    if not outcomes:
        return 'T2', decisive, 'Repeated related authentication failures are observed without a sufficiently supported outcome.'
    decisive = sorted({a for a,b in pairs if b in outcomes} | set(outcomes))
    post = findings['post_authentication_related_detections']
    later_ids = {a['id'] for a in post['value'].get('detections', [])}
    later = _pairs(post, evidence, success['refs'], later_ids, 'pairs')
    progression = [(a,b) for a,b in later if a in outcomes and _security(evidence[b])]
    if progression:
        return 'T4', sorted(set(decisive) | {b for a,b in progression}), 'Related failures preceded a directly observed success, followed by a linked security-category detection.'
    return 'T3', decisive, 'Repeated related authentication failures preceded the same directly observed successful authentication. Strong evidence requires analyst attention, not a confirmed compromise verdict.'


def _confidence(state, decisive, evidence, findings, asset, playbook):
    if state == 'Inconclusive':
        return 'low', 'Evidence does not support a defensible activity state.'
    rows = [evidence[i] for i in decisive]
    from app.services.archive_evidence import archive_coverage
    coverage = findings.get('archive_coverage', {})
    if playbook in (FILE_PROCESS, REMOTE_ACCESS) and archive_coverage(coverage.get('value')) == 'unavailable':
        return 'low', 'Relevant archive coverage was unavailable; source observations still support the evidence state.'
    checks = ('successful_authentication_after_failures','post_authentication_related_detections')
    unavailable = playbook == AUTH and any(
        findings.get(k,{}).get('status') not in ('observed','not_observed') for k in checks)
    unknown_later = any(not _security(a) for a in findings.get('post_authentication_related_detections',{}).get('value',{}).get('detections',[]))
    if (unavailable or unknown_later or any(event_time(a.get('event_timestamp')) is None
            or not (a.get('source_ip') or a.get('username') or
                    a.get('source_fields', {}).get('username')) for a in rows)):
        return 'low', 'Important temporal/entity or adjacent-state checks are unavailable or ambiguous; risk is not reduced.'
    if (not asset or any(not a.get('source_ip') or not a.get('username') for a in rows)
            or (playbook == FALLBACK and len(rows) != len(evidence))):
        return 'medium', 'Direct traceable evidence supports the state, but non-decisive context is incomplete.'
    return 'high', 'Decisive observations are directly traceable with required temporal/entity context and no unavailable key checks.'


def _load(connection, investigation):
    findings = {}
    for row in connection.execute('SELECT * FROM investigation_findings WHERE investigation_id=?', (investigation['id'],)):
        refs = {r[0] for r in connection.execute('SELECT alert_id FROM investigation_finding_alerts WHERE finding_id=?', (row['id'],))}
        refs.update(-r[0] for r in connection.execute('''SELECT archive_evidence_id
            FROM investigation_finding_archive_evidence WHERE finding_id=?''',(row['id'],)))
        findings[row['finding_key']] = {'id': row['id'], 'value': json.loads(row['finding_value']),
                                      'status':row['finding_status'], 'refs':refs}
    snapshot = findings['linked_alert_evidence']
    evidence = {a['id']: a for a in snapshot['value']}
    if set(evidence) != snapshot['refs'] or len(evidence) != len(snapshot['value']):
        raise ValueError('Evidence snapshot is incomplete or duplicated')
    stored = {r['id']: dict(r) for r in connection.execute('''SELECT a.* FROM alerts a
        JOIN case_alert_members ia ON ia.alert_id=a.id WHERE ia.incident_id=?''', (investigation['incident_id'],))}
    for aid, alert in evidence.items():
        if aid < 0:
            from app.services.investigation import _archive_row_as_alert
            incident = connection.execute('SELECT * FROM incidents WHERE id=?',
                                          (investigation['incident_id'],)).fetchone()
            archive_row = connection.execute('''SELECT e.* FROM investigation_archive_evidence e
                JOIN investigations r ON r.id=e.investigation_id
                WHERE e.id=? AND r.incident_id=?''',(-aid,investigation['incident_id'])).fetchone()
            trigger_agent_id = stored[incident['alert_id']]['agent_id'] if incident['alert_id'] in stored else None
            if (archive_row is None or
                    _archive_row_as_alert(archive_row,incident,trigger_agent_id) != alert):
                raise ValueError('Archive evidence snapshot no longer matches stored provenance')
            continue
        if aid not in stored:
            raise ValueError('Evidence no longer belongs to the incident')
        # Use findings for decisions; source rows only validate traceability.
        for key in ('wazuh_alert_id','event_timestamp','rule_id','source_ip','destination_ip','username','agent_id'):
            expected = stored[aid].get(key)
            if key in ('username','source_ip','destination_ip') and expected is None:
                recovered = (stored_reported_account(stored[aid]['raw_alert']) if key == 'username'
                             else stored_reported_source_ip(stored[aid]['raw_alert']) if key == 'source_ip'
                             else stored_reported_destination_ip(stored[aid]['raw_alert']))
                if alert.get(key) in (None, recovered):
                    continue
            if alert.get(key) != expected:
                raise ValueError('Evidence snapshot no longer matches stored source fields')
        if alert.get('rule_groups') is not None:
            stored_groups = json.loads(stored[aid]['rule_groups'] or 'null')
            if not isinstance(stored_groups,list) or sorted(stored_groups) != alert['rule_groups']:
                raise ValueError('Evidence categories do not match the stored source')
        if 'source_fields' in alert:
            expected_fields = _summary(stored[aid])['source_fields']
            for newly_supported in ('username', 'source_ip', 'destination_ip',
                                    'provider_name', 'channel', 'utc_time',
                                    'process_guid', 'destination_port'):
                if newly_supported not in alert['source_fields']:
                    expected_fields.pop(newly_supported, None)
            # Older snapshots predate the Security 4688 process-name alias.
            # Validate their original content without enriching or rewriting it.
            if (expected_fields.get('event_id') == '4688' and
                    'process_name' not in alert['source_fields']):
                expected_fields.pop('process_name', None)
            if alert['source_fields'] != expected_fields:
                raise ValueError('Allowlisted source fields no longer match stored raw evidence')
    for finding in findings.values():
        if not finding['refs'] <= set(evidence):
            raise ValueError('Finding references evidence outside the execution snapshot')
    return findings,evidence


def _asset(findings):
    finding = findings.get('asset_context', {})
    asset = finding.get('value') if finding.get('status') == 'observed' else None
    return asset if isinstance(asset,dict) else None


def _insert(connection, incident_id, investigation_id, stage, state, asset, risk, confidence, rationale, inputs):
    criticality = asset.get('criticality') if asset else None
    return connection.execute('''INSERT INTO risk_assessments(incident_id,investigation_id,
        assessment_stage,evidence_state,asset_criticality_snapshot,risk_level,confidence,rationale,
        methodology_version,inputs_snapshot) VALUES(?,?,?,?,?,?,?,?,?,?)''',
        (incident_id,investigation_id,stage,state,criticality if criticality in CRITICALITIES else None,
         risk,confidence,rationale,VERSION,json.dumps(inputs,ensure_ascii=True,allow_nan=False))).lastrowid


def _initial(connection, incident_id, investigation_id, evidence, asset):
    levels = [a.get('rule_level') for a in evidence.values() if type(a.get('rule_level')) is int]
    highest = max(levels) if levels else None
    return _insert(connection,incident_id,investigation_id,'initial',None,asset,None,'low',
        'Preliminary triage only. Highest observed Wazuh rule level: '+str(highest if highest is not None else 'unavailable')+
        '. Administrator asset criticality: '+str(asset.get('criticality') if asset else 'unavailable')+
        '. No validated initial-risk formula is defined; no final risk or urgency is inferred.',
        {'highest_wazuh_rule_level':highest,'alert_ids':sorted(evidence),'asset':asset})


def create_initial_assessment(incident_id):
    connection = get_db_connection()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            incident = connection.execute('SELECT * FROM incidents WHERE id=?',(incident_id,)).fetchone()
            if not incident:
                raise LookupError('Incident not found')
            evidence = {r['id']:dict(r) for r in connection.execute('''SELECT a.* FROM alerts a
                JOIN case_alert_members ia ON ia.alert_id=a.id WHERE ia.incident_id=?''',(incident_id,))}
            asset = connection.execute('SELECT id,criticality,is_protected FROM assets WHERE id=?',(incident['asset_id'],)).fetchone()
            return _initial(connection,incident_id,None,evidence,dict(asset) if asset else None)
    finally:
        connection.close()


def assess_investigation(incident_id, investigation_id):
    """Idempotent per completed execution/version. A rerun produces a new history row."""
    connection = get_db_connection()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            investigation = connection.execute('SELECT * FROM investigations WHERE id=? AND incident_id=?',
                                               (investigation_id,incident_id)).fetchone()
            if not investigation:
                raise LookupError('Investigation not found')
            if investigation['status'] != 'completed':
                raise ValueError('Only completed investigations can be assessed')
            if investigation['playbook_key'] == 'wazuh_archive_retrieval_v1':
                raise ValueError('Archive retrieval alone cannot be contextually assessed')
            existing = connection.execute("SELECT id FROM risk_assessments WHERE investigation_id=? AND assessment_stage='contextual' AND methodology_version=?",
                                          (investigation_id,VERSION)).fetchone()
            if existing:
                return existing['id']
            findings, evidence, asset, decisive = {}, {}, None, []
            try:
                findings,evidence = _load(connection,investigation)
                asset = _asset(findings)
                state,decisive,reason = _state(investigation['playbook_key'], findings, evidence)
                confidence,confidence_reason = _confidence(state,decisive,evidence,findings,asset,investigation['playbook_key'])
            except (ValueError,TypeError,KeyError,AttributeError):
                state,confidence = 'Inconclusive','low'
                reason = 'Required findings are missing, contradictory, malformed or no longer traceable. Re-run the investigation.'
                confidence_reason = 'Supporting evidence cannot be reliably validated.'
            criticality = asset.get('criticality') if asset else None
            protected = bool(asset and asset.get('is_protected') == 1)
            risk = matrix_risk(state,criticality,protected)
            if state == 'Inconclusive':
                matrix_reason = 'Contextual risk could not be determined from the available investigation evidence.'
            elif asset and not protected:
                matrix_reason = 'Contextual Risk: Not calculated — Risk Assessment disabled for this asset.'
            elif criticality not in CRITICALITIES:
                matrix_reason = 'Contextual risk is Unassessed: a mapped asset with valid administrator criticality is unavailable in the investigation snapshot.'
            else:
                matrix_reason = f'CDSS qualitative matrix: {state} + {criticality} asset criticality = {risk} contextual risk.'
            rationale = f'Evidence State: {state} — {LABELS[state]}. {reason} {matrix_reason} Confidence: {confidence}. {confidence_reason} Project-defined CDSS methodology; not Wazuh/MITRE levels and not a compromise verdict.'
            _initial(connection,incident_id,investigation_id,evidence,asset)
            return _insert(connection,incident_id,investigation_id,'contextual',state,asset,risk,confidence,rationale,
                {'decisive_evidence_ids':decisive,
                 'decisive_alert_ids':[item for item in decisive if item > 0],
                 'decisive_archive_evidence_ids':[-item for item in decisive if item < 0],
                 'finding_ids':[f['id'] for f in findings.values()],
                 'asset':asset,'playbook_key':investigation['playbook_key'],
                 'evidence_reason':reason,
                 'not_observed_findings':[key for key, value in findings.items()
                                          if value['status']=='not_observed'],
                 'unavailable_findings':[key for key, value in findings.items()
                                         if value['status']=='unavailable']})
    finally:
        connection.close()


def assessment_history(connection, incident_id):
    return [dict(r) for r in connection.execute('SELECT * FROM risk_assessments WHERE incident_id=? ORDER BY id DESC',(incident_id,))]


def current_assessment(connection, incident_id):
    row = connection.execute("SELECT * FROM risk_assessments WHERE incident_id=? AND assessment_stage='contextual' ORDER BY id DESC LIMIT 1",(incident_id,)).fetchone()
    return dict(row) if row else None
