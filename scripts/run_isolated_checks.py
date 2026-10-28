"""Run unittest with a disposable outer database, including discovery imports."""
import hashlib
from contextlib import closing
import json
from pathlib import Path
import sqlite3
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / 'tests')]
import app.database as database


with tempfile.TemporaryDirectory() as directory, patch.object(database, 'DATABASE', Path(directory) / 'outer.db'):
    from app.database.seed import seed_knowledge_base
    seed_knowledge_base()
    before = database.DATABASE.read_bytes()
    original_connect = sqlite3.connect
    writes = []
    def connect(*args, **kwargs):
        target = str(args[0])
        main_path = ROOT / 'data' / 'cdss.db'
        if (target.startswith(main_path.as_uri()) or
                (not target.startswith('file:') and Path(target).resolve()==main_path.resolve())):
            raise RuntimeError('Automated checks must not open the main database')
        connection = original_connect(*args, **kwargs)
        if str(args[0]) == str(database.DATABASE) and str(args[0]).endswith('outer.db'):
            connection.set_trace_callback(lambda sql: writes.append(sql) if sql.lstrip().upper().startswith(('UPDATE','INSERT','DELETE','ALTER','CREATE','DROP')) else None)
        return connection
    mode = sys.argv[1] if len(sys.argv) > 1 else 'target'
    with patch('sqlite3.connect', side_effect=connect):
        if mode == 'target':
            suite = unittest.defaultTestLoader.loadTestsFromName('test_reference_evaluation.ReferenceEvaluationTests.test_real_pipeline_repeatability_integrity_and_explainability')
        else:
            suite = unittest.defaultTestLoader.discover(str(ROOT / 'tests'), pattern=sys.argv[3] if len(sys.argv)>3 else 'test_*.py')
        log_name = sys.argv[2] if len(sys.argv)>2 else 't4_tests_' + mode + '.log'
        with (ROOT / log_name).open('w', encoding='utf-8') as stream:
            result = unittest.TextTestRunner(verbosity=2, stream=stream).run(suite)
    print('TESTS', result.testsRun, 'FAILURES', len(result.failures), 'ERRORS', len(result.errors))
    for test, error in result.failures + result.errors:
        print('FAILED',str(test),error.splitlines()[-1][:300])
    after = database.DATABASE.read_bytes()
    print('OUTER_DATABASE_CHANGED', before != after)
    print('BYTE_DIFF_OFFSETS', [i for i,(a,b) in enumerate(zip(before,after)) if a != b][:40])
    print('OUTER_WRITE_STATEMENTS', len(writes))
    with closing(original_connect(database.DATABASE)) as connection:
        from app.time_utils import epoch_seconds
        connection.create_function('cdss_event_epoch',1,epoch_seconds,deterministic=True)
        print('INTEGRITY', connection.execute('PRAGMA integrity_check').fetchall())
        print('FK', connection.execute('PRAGMA foreign_key_check').fetchall())
    sys.exit(not result.wasSuccessful())
