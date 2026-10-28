"""Read-only saved-case audit; never initializes application storage."""
import json
import sqlite3
import sys
import contextlib
import csv
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.services.contextual_risk import _load, _file_related, _state, _confidence, _asset
from app.services.investigation import _file_events


def main():
    db = sqlite3.connect('file:data/cdss.db?mode=ro', uri=True)
    db.row_factory = sqlite3.Row
    try:
        assessments = [dict(r) for r in db.execute("SELECT * FROM risk_assessments WHERE incident_id=11331 AND assessment_stage='contextual' ORDER BY id DESC")]
        print('ASSESSMENTS', json.dumps(assessments))
        runs = [dict(r) for r in db.execute('SELECT r.* FROM investigation_archive_runs r JOIN investigations i ON i.id=r.investigation_id WHERE i.incident_id=11331')]
        print('RUNS', json.dumps(runs))
        for row in db.execute('SELECT e.* FROM investigation_archive_evidence e JOIN investigations i ON i.id=e.investigation_id WHERE i.incident_id=11331 ORDER BY e.id'):
            f = json.loads(row['selected_fields_json'])
            if f.get('event_id') in ('1','11'):
                print('RETAINED', json.dumps(dict(row)))
        if assessments:
            inv = db.execute('SELECT * FROM investigations WHERE id=?', (assessments[0]['investigation_id'],)).fetchone()
            findings, evidence = _load(db, inv)
            events = _file_events(evidence.values())
            for p in (e for e in events if e['kind']=='process'):
                for f in (e for e in events if e['kind']=='file'):
                    def details(e):
                        a = evidence[e['alert_id']]
                        return dict(id=e['alert_id'], timestamp=a['event_timestamp'], **a['source_fields'])
                    print('PAIR', json.dumps(dict(process=details(p), file=details(f), related=_file_related(p,f,evidence))))
            state, decisive, reason = _state(inv['playbook_key'], findings, evidence)
            print('REPLAY', json.dumps(dict(state=state, decisive=decisive, reason=reason, confidence=_confidence(state,decisive,evidence,findings,_asset(findings),inv['playbook_key']), asset=_asset(findings), coverage=findings.get('archive_coverage')), default=list))
            for eid in decisive:
                print('DECISIVE', json.dumps(evidence[eid]))
        print('INTEGRITY', db.execute('PRAGMA integrity_check').fetchall()[0][0])
        print('FK', [tuple(r) for r in db.execute('PRAGMA foreign_key_check')])
        for table, column, parent in (
            ('case_alert_members','alert_id','alerts'),
            ('case_alert_members','incident_id','incidents'),
            ('investigation_archive_evidence','investigation_id','investigations'),
            ('investigation_findings','investigation_id','investigations'),
            ('risk_assessments','investigation_id','investigations')):
            count=db.execute(f'SELECT COUNT(*) FROM {table} c LEFT JOIN {parent} p ON p.id=c.{column} WHERE c.{column} IS NOT NULL AND p.id IS NULL').fetchone()[0]
            print('ORPHANS',table,column,count)
        print('DUPLICATE_ARCHIVE_DOCUMENTS',db.execute('SELECT COUNT(*) FROM (SELECT investigation_id,source_index,source_document_id FROM investigation_archive_evidence GROUP BY investigation_id,source_index,source_document_id HAVING COUNT(*)>1)').fetchone()[0])
    finally:
        db.close()


if __name__ == '__main__':
    output = Path(sys.argv[1] if len(sys.argv)>1 else 't4_audit_before.txt')
    with output.open('w', encoding='utf-8') as stream, contextlib.redirect_stdout(stream):
        main()
    for line in output.read_text(encoding='utf-8').splitlines():
        if line.startswith(('REPLAY', 'DECISIVE', 'INTEGRITY', 'FK', 'ORPHANS', 'DUPLICATE')):
            print(line)
    pairs=[json.loads(line[5:]) for line in output.read_text(encoding='utf-8').splitlines() if line.startswith('PAIR ')]
    baseline=Path('t4_audit_before.txt')
    old_pairs={}
    if baseline.exists():
        old_pairs={(p['process']['id'],p['file']['id']):p['related'] for p in
                   (json.loads(line[5:]) for line in baseline.read_text(encoding='utf-8').splitlines() if line.startswith('PAIR '))}
        print('HISTORICAL_ASSESSMENTS_UNCHANGED',baseline.read_text(encoding='utf-8').splitlines()[0] == output.read_text(encoding='utf-8').splitlines()[0])
    columns=['id','timestamp','utc_time','process_id','process_guid','process_name','username','file_path']
    with output.with_suffix('.csv').open('w',encoding='utf-8',newline='') as stream:
        writer=csv.writer(stream)
        writer.writerow([side+'_'+key for side in ('process','file') for key in columns]+['_file_related','_file_related_before'])
        for pair in pairs:
            writer.writerow([pair[side].get(key) for side in ('process','file') for key in columns]+[pair['related'],old_pairs.get((pair['process']['id'],pair['file']['id']))])
    print('PAIRS_ENUMERATED',len(pairs))
