"""Normal Flask application on a disposable backup; never writes the source DB."""
import json,os,pathlib,secrets,sqlite3,sys,tempfile
from contextlib import closing
root,source,out=map(pathlib.Path,sys.argv[1:4])
sys.path.insert(0,str(root))
os.environ['CDSS_REALTIME_ENABLED']='false'
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server
import app.database as database
with tempfile.TemporaryDirectory(prefix='browser-db-',dir=out) as directory:
    database.DATABASE=pathlib.Path(directory)/'disposable.db'
    with closing(sqlite3.connect(source.as_uri()+'?mode=ro',uri=True)) as original:
        with closing(sqlite3.connect(database.DATABASE)) as copy:
            original.backup(copy)
    from run import app,prepare_runtime
    prepare_runtime()
    password=secrets.token_urlsafe(24)
    with closing(database.get_db_connection()) as db,db:
        db.execute('UPDATE siem_connections SET is_enabled=0')
        db.execute('INSERT INTO users(username,password_hash,role) VALUES(?,?,?)',
                   ('browser-disposable-admin',generate_password_hash(password,method='scrypt'),'admin'))
    (out/'browser-disposable-credentials.json').write_text(json.dumps({'username':'browser-disposable-admin','password':password}),encoding='utf-8')
    print('DISPOSABLE_BROWSER_SERVER_READY 127.0.0.1:5001',flush=True)
    with make_server('127.0.0.1',5001,app,threaded=True) as server:
        server.serve_forever()
