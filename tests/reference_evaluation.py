"""Offline evaluation utility. Run: python tests/reference_evaluation.py

Outputs machine-readable evaluation data to stdout only; writes no result file.
Labels are provisional judgments requiring human/supervisor review, not ground truth.
"""
import hashlib
import json
from pathlib import Path
import sys
import tempfile
from types import MappingProxyType
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

PRIORITIES = ('Low', 'Medium', 'High')
# Frozen before executing any scenario. No access to manual labels in this map.
RISK_TO_REFERENCE = MappingProxyType({'low':'Low','medium':'Medium','high':'High','critical':'High'})
DATASET = Path(__file__).parent / 'fixtures' / 'reference_priorities.json'
METHOD_FILES = ('contextual_risk.py','incident_correlation.py','investigation.py','contextual_recommendations.py')


def load_dataset(path=DATASET):
    data = json.loads(Path(path).read_text(encoding='utf-8'))
    if data.get('label_status') not in ('draft','reviewed') or not data.get('scenarios'):
        raise ValueError('Dataset requires scenarios and honest review status')
    ids = set()
    for row in data['scenarios']:
        for field in ('scenario_id','scenario_name','description','expected_evidence','reference_rationale'):
            if not isinstance(row.get(field),str) or not row[field].strip():
                raise ValueError('Missing scenario text: '+field)
        if row['scenario_id'] in ids:
            raise ValueError('Duplicate scenario ID')
        ids.add(row['scenario_id'])
        if row.get('reference_priority') not in PRIORITIES:
            raise ValueError('Reference labels must be Low, Medium or High')
        if row.get('asset_criticality') not in ('low','medium','high','critical'):
            raise ValueError('Invalid criticality')
        if row.get('sequence') not in ('isolated','repeated','success','progressed','fallback'):
            raise ValueError('Unknown fixture sequence')
        if row.get('label_status') not in ('draft','reviewed'):
            raise ValueError('Invalid review status')
    return data


def mapped_priority(risk):
    if risk is None or risk == 'unassessed':
        return 'Unassessed'
    if risk not in RISK_TO_REFERENCE:
        raise ValueError('Unknown contextual risk')
    return RISK_TO_REFERENCE[risk]


def summarize(results):
    matrix = {r:{c:0 for c in PRIORITIES} for r in PRIORITIES}
    matches = assessed = 0
    for row in results:
        reference, predicted = row['reference_priority'], row['mapped_priority']
        if reference not in PRIORITIES:
            raise ValueError('Invalid reference priority')
        if predicted == 'Unassessed':
            continue
        if predicted not in PRIORITIES:
            raise ValueError('Invalid predicted priority')
        assessed += 1
        matches += reference == predicted
        matrix[reference][predicted] += 1
    return {'assessed':assessed,'unassessed':len(results)-assessed,'exact_matches':matches,
            'agreement_percentage':round(100*matches/assessed,2) if assessed else None,
            'disagreements':assessed-matches,'confusion_matrix':matrix,
            'matrix_rows':'reference priority','matrix_columns':'CDSS mapped priority'}


def trace_valid(db, incident, assessment):
    from app.services.contextual_risk import _load
    investigation = db.execute('SELECT * FROM investigations WHERE id=? AND incident_id=?',
                               (assessment['investigation_id'],incident)).fetchone()
    if not investigation or investigation['status']!='completed':
        return False
    try:
        loaded, evidence = _load(db,investigation)
        inputs = json.loads(assessment['inputs_snapshot'])
        if (set(inputs['finding_ids'])!={f['id'] for f in loaded.values()}
                or not set(inputs.get('decisive_evidence_ids',inputs['decisive_alert_ids'])) <= set(evidence)
                or inputs['asset']['criticality']!=assessment['asset_criticality_snapshot']):
            return False
    except (ValueError,TypeError,KeyError,AttributeError):
        return False
    alerts = db.execute('''SELECT a.* FROM alerts a JOIN case_alert_members ia ON ia.alert_id=a.id
        WHERE ia.incident_id=?''',(incident,)).fetchall()
    refs = {r[0] for r in db.execute('''SELECT fa.alert_id FROM investigation_finding_alerts fa
        JOIN investigation_findings f ON f.id=fa.finding_id WHERE f.investigation_id=?''',
        (assessment['investigation_id'],))}
    findings = db.execute('SELECT * FROM investigation_findings WHERE investigation_id=?',
                          (assessment['investigation_id'],)).fetchall()
    recs = db.execute('SELECT * FROM contextual_recommendations WHERE assessment_id=? AND incident_id=?',
                      (assessment['id'],incident)).fetchall()
    asset = db.execute('SELECT a.criticality FROM assets a JOIN incidents i ON i.asset_id=a.id WHERE i.id=?',
                       (incident,)).fetchone()
    for recommendation in recs:
        snapshot=json.loads(recommendation['evidence_snapshot'])
        if (snapshot['assessment_id']!=assessment['id'] or snapshot['investigation_id']!=investigation['id']
                or not set(snapshot['alert_ids']) <= set(evidence)
                or not {-item for item in snapshot.get('archive_evidence_ids',[])} <= set(evidence)
                or set(snapshot['finding_ids'])!={f['id'] for f in loaded.values()}):
            return False
    return bool(alerts and refs == {r['id'] for r in alerts} and findings and recs and asset
        and asset[0] == assessment['asset_criticality_snapshot'] and assessment['rationale']
        and all(json.loads(r['raw_alert'])['id']==r['wazuh_alert_id'] and r['processing_status']=='processed' for r in alerts)
        and all(r['rationale'] and json.loads(r['evidence_snapshot']) for r in recs)
        and all(r[0] for r in db.execute('SELECT correlation_reason FROM case_alert_members WHERE incident_id=?',(incident,)))
        and not db.execute('PRAGMA foreign_key_check').fetchall())


def methodology_digest():
    return {name:hashlib.sha256((ROOT/'app/services'/name).read_bytes()).hexdigest() for name in METHOD_FILES}


def stable_evidence(value):
    """Exclude database insertion times, not source event times, from comparison."""
    if isinstance(value,dict):
        return {k:stable_evidence(v) for k,v in value.items() if k not in ('created_at','updated_at')}
    if isinstance(value,list):
        return [stable_evidence(v) for v in value]
    return value


def evaluate(path=DATASET):
    # Freeze inputs before importing/executing application services.
    original = Path(path).read_bytes()
    dataset = load_dataset(path)
    before = methodology_digest()
    import app.database as database
    # First Flask import initializes only a disposable bootstrap DB, never the
    # development DB. Every scenario then uses the Phase 9 isolated harness.
    with tempfile.TemporaryDirectory() as directory, patch.object(database,'DATABASE',Path(directory)/'bootstrap.db'):
        import test_phase9_end_to_end as harness
        results = []
        for scenario in dataset['scenarios']:
            fixture = harness.PhaseNineEndToEndTests('runTest')
            try:
                fixture.setUp()
                fixture.post(f"/admin/assets/{fixture.asset['id']}/edit",
                    asset_name='Reference evaluation asset',asset_type='Server',asset_role='Authentication Server',
                    os_family='Linux',os_name='Ubuntu Server',wazuh_agent_id='phase9-agent',
                    criticality=scenario['asset_criticality'],is_protected='1')
                sequence = scenario['sequence']
                groups = ['windows'] if sequence=='fallback' else ['authentication_failed']
                if sequence in ('repeated','success','progressed'):
                    groups.append('authentication_failed')
                if sequence in ('success','progressed'):
                    groups.append('authentication_success')
                if sequence=='progressed':
                    groups.append('syscheck')
                for minute,group in enumerate(groups):
                    ids = ['T1110'] if group=='authentication_failed' else ['T1078','T1078.002'] if group=='authentication_success' else None
                    fixture.event(scenario['scenario_id']+str(minute),minute,group,ids)
                harness._poll_once(100,0)
                db = fixture.db
                if db.execute('SELECT COUNT(*) FROM incidents').fetchone()[0]!=0:
                    raise AssertionError('Polling must not open an analyst case')
                _,incident=fixture.investigate_group()
                assessment = db.execute("SELECT * FROM risk_assessments WHERE incident_id=? AND assessment_stage='contextual' ORDER BY id DESC",(incident,)).fetchone()
                predicted = mapped_priority(assessment['risk_level'])
                agreement = 'unassessed' if predicted=='Unassessed' else 'yes' if predicted==scenario['reference_priority'] else 'no'
                reason = ''
                if agreement!='yes':
                    reason = ('Expected abstention: generic evidence has no dedicated supported activity-state conclusion. ' if agreement=='unassessed' else
                              'Methodological difference, not an automatic defect: CDSS evidence/asset rules and the draft analyst judgment assign different urgency. ')
                    reason += 'Reference rationale: '+scenario['reference_rationale']+' CDSS rationale: '+assessment['rationale']
                results.append({'scenario_id':scenario['scenario_id'],'reference_priority':scenario['reference_priority'],
                    'label_status':scenario['label_status'],'evidence_state':assessment['evidence_state'],
                    'contextual_risk':assessment['risk_level'],'mapped_priority':predicted,
                    'confidence':assessment['confidence'],'agreement':agreement,'explanation':reason,
                    'rationale':assessment['rationale'],'explainability':'passed' if trace_valid(db,incident,assessment) else 'failed',
                    'trace':{'source_alert_ids':[r[0] for r in db.execute('SELECT wazuh_alert_id FROM alerts ORDER BY id')],
                        'correlation_reasons':[r[0] for r in db.execute('SELECT correlation_reason FROM case_alert_members WHERE incident_id=? ORDER BY ordinal',(incident,))],
                        'assessment_inputs':json.loads(assessment['inputs_snapshot']),
                        'findings':[{'id':r['id'],'key':r['finding_key'],'status':r['finding_status'],
                                     'value':stable_evidence(json.loads(r['finding_value']))}
                                    for r in db.execute('SELECT id,finding_key,finding_status,finding_value FROM investigation_findings ORDER BY id')],
                        'recommendation_rules':[r[0] for r in db.execute('SELECT rule_key FROM contextual_recommendations ORDER BY priority')]}})
            finally:
                if hasattr(fixture,'db'):
                    fixture.tearDown()
                fixture.doCleanups()
    if Path(path).read_bytes()!=original or methodology_digest()!=before:
        raise AssertionError('Evaluation mutated labels or methodology')
    return {'boundary':'Offline controlled draft-reference evaluation; not live detection accuracy',
            'dataset_sha256':hashlib.sha256(original).hexdigest(),'label_status':dataset['label_status'],
            'results':results,**summarize(results)}


if __name__=='__main__':
    print(json.dumps(evaluate(),indent=2))
