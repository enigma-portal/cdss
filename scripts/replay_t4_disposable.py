"""Replay saved Case 11331 on a temporary SQLite backup; no SIEM collection."""
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
from unittest.mock import patch

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
import app.database as database


with tempfile.TemporaryDirectory() as directory:
    replay_db=Path(directory)/'replay.db'
    with closing(sqlite3.connect('file:'+str(ROOT/'data/cdss.db')+'?mode=ro',uri=True)) as source:
        with closing(sqlite3.connect(replay_db)) as destination:
            source.backup(destination)
    with patch.object(database,'DATABASE',replay_db), patch('socket.socket.connect',side_effect=AssertionError('Offline replay forbids network')):
        from app.services.investigation import run_investigation, investigation_history
        from app.services.contextual_risk import assess_investigation
        from app.services.evidence_progression import evidence_progression
        from app.services.contextual_recommendations import generate_contextual_recommendations
        with closing(database.get_db_connection()) as connection:
            history=[tuple(r) for r in connection.execute('SELECT * FROM risk_assessments ORDER BY id')]
        execution=run_investigation(11331)
        assessment_id=assess_investigation(11331,execution)
        generate_contextual_recommendations(11331)
        from run import app
        with closing(database.get_db_connection()) as connection, connection:
            user_id=connection.execute("INSERT INTO users(username,password_hash,role) VALUES('offline-replay-review','unused','analyst')").lastrowid
        client=app.test_client()
        with client.session_transaction() as session:
            session['user_id']=user_id
        response=client.get('/incidents/11331')
        assert response.status_code==200
        html=response.data.decode()
        section=html.split('id="evidence-progression"',1)[1].split('id="investigation"',1)[0]
        decisive_html=section.split('Other/background observations',1)[0]
        assert 'OneDrive' not in decisive_html
        actions=html.split('id="contextual-guidance"',1)[1].split('id="analyst-decision"',1)[0]
        assert 'contextual assessment scope' not in actions
        with closing(database.get_db_connection()) as connection:
            assessment=dict(connection.execute('SELECT * FROM risk_assessments WHERE id=?',(assessment_id,)).fetchone())
            old=[tuple(r) for r in connection.execute('SELECT * FROM risk_assessments WHERE id<=? ORDER BY id',(history[-1][0],))]
            assert history==old, 'Historical assessments changed on disposable replay'
            investigation=next(r for r in investigation_history(connection,11331) if r['id']==execution)
            view=evidence_progression(assessment,investigation)
            report=json.dumps(dict(assessment=assessment,progression=view['decisive'],coverage=view['coverage'],
                                  background_count=len(view['background']),historical_assessments_unchanged=True,
                                  rendered_case_status=response.status_code,background_networks_separated=True,
                                  asset_configuration_recommendation_removed=True,
                                  integrity=connection.execute('PRAGMA integrity_check').fetchone()[0],
                                  foreign_key_violations=[tuple(r) for r in connection.execute('PRAGMA foreign_key_check')]),indent=2)
            (ROOT/'t4_replay.json').write_text(report,encoding='utf-8')
            print(report)
