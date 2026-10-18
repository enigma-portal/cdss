"""Approved CDSS project guidance, not externally verified framework mappings.

Consumes existing assessment and evidence; never calculates risk, executes response,
changes incident status, or records a decision on behalf of a person.
Legacy guidance/weights are intentionally not read or written by this module.
"""
import json

from app.database import get_db_connection
from app.services.contextual_risk import current_assessment, _load, _security, _state
from app.services.investigation import AUTH, FALLBACK
from app.services.playbook_registry import FILE_PROCESS, REMOTE_ACCESS

VERSION = 'cdss-guidance-v2'
DECISIONS = {'accept','reject','further_investigation_required'}


def _select(connection, assessment):
    investigation = connection.execute('SELECT * FROM investigations WHERE id=? AND incident_id=?',
        (assessment['investigation_id'],assessment['incident_id'])).fetchone()
    if not investigation or investigation['status'] != 'completed':
        raise ValueError('A completed investigation is required')
    findings,evidence,decisive,validated = {},{},set(),False
    try:
        findings,evidence = _load(connection,investigation)
        snapshot = json.loads(assessment['inputs_snapshot'])
        state, ids, _ = _state(investigation['playbook_key'], findings, evidence)
        if (state != assessment['evidence_state'] or
                set(ids) != set(snapshot.get('decisive_evidence_ids',
                                            snapshot.get('decisive_alert_ids', []))) or
                snapshot.get('playbook_key') != investigation['playbook_key']):
            raise ValueError('Saved assessment and investigation evidence disagree')
        decisive = set(ids)
        validated = True
    except (ValueError,TypeError,KeyError,AttributeError):
        findings,evidence,decisive = {},{},set()
    selected = []

    def add(key,category,text,reason,ids=()):
        selected.append(dict(rule_key=key, category=category, action_text=text,
            rationale=reason, source_reference='CDSS project guidance / '+VERSION+'/'+investigation['playbook_key'],
            evidence_snapshot=json.dumps({'assessment_id':assessment['id'],
                'investigation_id':assessment['investigation_id'],
                'alert_ids':sorted({item for item in ids if type(item) is int and item > 0}),
                'archive_evidence_ids':sorted({-item for item in ids if type(item) is int and item < 0}),
                'finding_ids':sorted(f['id'] for f in findings.values())}, sort_keys=True)))

    playbook = investigation['playbook_key']
    state = assessment['evidence_state']
    asset = findings.get('asset_context', {}).get('value')
    asset = asset if isinstance(asset, dict) else None
    # Assessment scope controls the matrix result, not whether traceable
    # playbook observations can support conservative analyst guidance.
    safe = assessment['evidence_state']=='Inconclusive' or not evidence
    if safe:
        if not validated:
            action = 'Revalidate the saved evidence and asset context, then re-run investigation and assessment.'
            why = 'The saved investigation evidence could not be verified against its assessment.'
        elif not asset:
            action = 'Identify the affected asset and obtain missing source evidence, then re-run investigation and assessment.'
            why = 'No configured asset is linked to the saved investigation evidence.'
        elif not asset.get('is_protected'):
            action = 'Confirm whether this asset belongs in contextual assessment scope; if changed, re-run investigation and assessment.'
            why = 'The mapped asset is outside contextual assessment scope.'
        else:
            action = 'Obtain missing or contradictory evidence, then re-run investigation and assessment.'
            why = 'The saved investigation does not establish a defensible contextual assessment.'
        add('obtain_context','Investigation',action,why,evidence)
        if playbook == FALLBACK and evidence:
            add('generic_review','Investigation','Validate the available alert and reported source with the asset owner.',
                'No dedicated playbook matched the linked alert evidence.',evidence)
        add('monitor','Monitoring','Watch for additional related activity while the missing context is obtained.',
            'Current evidence does not support a specific response action.',evidence)
        return selected

    if asset is None:
        add('confirm_asset_scope','Investigation','Identify the affected asset and confirm its assessment scope.',
            'No configured asset was present in the saved investigation context.',decisive)
    elif not asset.get('is_protected'):
        add('confirm_asset_scope','Investigation','Confirm whether the mapped asset should be included in contextual assessment scope.',
            'The saved asset is outside contextual assessment scope.',decisive)

    if playbook in (AUTH,REMOTE_ACCESS):
        remote = playbook == REMOTE_ACCESS
        failure = findings.get('authentication_failures',{})
        success = findings.get('successful_authentication',{})
        sequence = findings.get('successful_authentication_after_failures',{})
        if remote:
            observed = findings.get('remote_access_events',{}).get('value',[])
            if state == 'T1':
                add('review_remote','Investigation','Validate the reported remote source, destination and account authorization.',
                    'One remote-service authentication observation is recorded.',decisive)
            elif state == 'T2':
                add('review_remote','Investigation','Review the related remote authentication pattern and account authorization.',
                    'Related remote-service authentication observations share reported context.',decisive)
            else:
                add('validate_success','Investigation','Validate the related remote logon and account authorization.',
                    'Related remote failures preceded a recorded successful logon.',sequence.get('refs',decisive))
            cross_host = state == 'T4' and any(
                item.get('alert_id') in decisive and item.get('outcome') == 'success' and
                item.get('agent_id') != next((e.get('agent_id') for e in observed
                    if e.get('alert_id') in decisive and e.get('outcome') == 'failure'), item.get('agent_id'))
                for item in observed)
            if cross_host:
                add('review_other_systems','Investigation','Check the other observed system for related account activity.',
                    'A later remote logon was recorded on a different reported agent.',decisive)
        else:
            if state in ('T1','T2'):
                add('review_authentication','Investigation',
                    'Validate the recorded authentication failure and reported account/source.' if state=='T1' else
                    'Review the related failures and verify the reported account/source.',
                    'A failure is recorded without related repetition.' if state=='T1' else
                    'Separate related authentication failures are recorded.',decisive)
            else:
                add('validate_success','Investigation','Verify whether the related successful authentication was authorized.',
                    'Repeated related failures preceded the same recorded successful authentication.',sequence.get('refs',decisive))
        if state == 'T4':
            later = [i for i in decisive if i in evidence and _security(evidence[i]) and
                     i not in failure.get('refs',set()) and i not in success.get('refs',set())]
            if later:
                add('review_post_activity','Investigation','Review the later security detection against approved activity.',
                    'A linked security-category detection followed the related logon.',later)
            if assessment['risk_level'] is not None and (later or (remote and cross_host)):
                reason = ('A later logon on a different reported agent requires authorization review.'
                          if remote and cross_host and not later else
                          'A later linked security-category detection requires authorization review.')
                add('consider_containment','Containment',
                    'If unauthorized activity is substantiated, consider a narrowly scoped response after analyst approval.',
                    reason,later or decisive)
        add('monitor','Monitoring','Monitor the reported account/source for additional related authentication activity.',
            'The recorded authentication pattern warrants follow-up observations.',decisive)
    elif playbook == FILE_PROCESS:
        events = findings['file_process_events']['value']
        if state == 'T1':
            noun = 'observation' if len(events) == 1 else 'observations'
            verb = 'is' if len(events) == 1 else 'are'
            add('review_file_origin','Investigation','Validate the reported file or process origin.',
                f'{len(events)} structured file/process {noun} {verb} recorded without related file-and-process corroboration.',
                decisive)
        else:
            add('review_lineage','Investigation','Inspect the related file and process lineage.',
                'Related file and process observations share a reported artifact or process.',decisive)
            if state in ('T3','T4'):
                add('review_command','Investigation','Validate the recorded command line against authorized activity.',
                    'The related process observation includes a reported command line.',decisive)
        if state == 'T4':
            later = [item for item in events if item['alert_id'] in decisive and item['kind'] in ('network','integrity')]
            if later:
                add('review_follow_on','Investigation','Review the later related network or integrity detection.',
                    'A later linked network or integrity observation is recorded.',[item['alert_id'] for item in later])
                if assessment['risk_level'] is not None:
                    add('consider_containment','Containment','If the related activity is confirmed unauthorized, consider scoped containment with analyst approval.',
                        'Related file/process observations were followed by a linked security-relevant detection.',decisive)
        add('monitor','Monitoring','Watch for further related file or process activity on the affected system.',
            'Follow-up observations can clarify the recorded file/process activity.',decisive)
    else:
        add('generic_review','Investigation','Validate the available alert and reported source with the asset owner.',
            'No dedicated playbook matched the linked alert evidence.',evidence)
        add('monitor','Monitoring','Watch for additional related activity.',
            'The available alert does not support an attack-specific response.',evidence)
    return selected[:5]


def generate_contextual_recommendations(incident_id):
    """Persist one deterministic set for the latest contextual assessment/version."""
    connection=get_db_connection()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            assessment=current_assessment(connection,incident_id)
            if not assessment:
                raise ValueError('A contextual assessment is required')
            existing=connection.execute('SELECT id FROM contextual_recommendations WHERE assessment_id=? AND methodology_version=? ORDER BY priority,id',
                                        (assessment['id'],VERSION)).fetchall()
            if existing:
                return [r['id'] for r in existing]
            ids=[]
            for order,item in enumerate(_select(connection,assessment),1):
                ids.append(connection.execute('''INSERT INTO contextual_recommendations
                    (incident_id,assessment_id,rule_key,category,priority,action_text,source_reference,
                     rationale,evidence_snapshot,methodology_version) VALUES(?,?,?,?,?,?,?,?,?,?)''',
                    (incident_id,assessment['id'],item['rule_key'],item['category'],order,item['action_text'],
                     item['source_reference'],item['rationale'],item['evidence_snapshot'],VERSION)).lastrowid)
            return ids
    finally:
        connection.close()


def record_analyst_decision(incident_id,assessment_id,recommendation_id,user_id,decision,comments=''):
    if decision not in DECISIONS:
        raise ValueError('Select a valid analyst decision')
    if not isinstance(comments,str) or len(comments)>4000:
        raise ValueError('Comments must be at most 4000 characters')
    connection=get_db_connection()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            user=connection.execute('SELECT * FROM users WHERE id=?',(user_id,)).fetchone()
            if not user or not user['is_active'] or user['role'] not in ('admin','analyst'):
                raise PermissionError('An active analyst or administrator is required')
            assessment=current_assessment(connection,incident_id)
            if not assessment or assessment['id'] != assessment_id:
                raise ValueError('Assessment has changed. Refresh and review current guidance before deciding')
            if recommendation_id is None:
                exists=connection.execute('SELECT 1 FROM contextual_recommendations WHERE incident_id=? AND assessment_id=?',
                    (incident_id,assessment_id)).fetchone()
            else:
                exists=connection.execute('SELECT 1 FROM contextual_recommendations WHERE id=? AND incident_id=? AND assessment_id=?',
                    (recommendation_id,incident_id,assessment_id)).fetchone()
            if not exists:
                raise LookupError('Contextual recommendation not found')
            return connection.execute('''INSERT INTO analyst_decisions(incident_id,assessment_id,
                incident_recommendation_id,user_id,analyst_name_snapshot,decision,comments) VALUES(?,?,?,?,?,?,?)''',
                (incident_id,assessment_id,recommendation_id,user_id,user['username'],decision,comments)).lastrowid
    finally:
        connection.close()


def recommendation_history(connection,incident_id):
    return [dict(r) for r in connection.execute('SELECT * FROM contextual_recommendations WHERE incident_id=? ORDER BY assessment_id DESC,priority,id',(incident_id,))]


def decision_history(connection,incident_id):
    return [dict(r) for r in connection.execute('SELECT * FROM analyst_decisions WHERE incident_id=? ORDER BY id DESC',(incident_id,))]
