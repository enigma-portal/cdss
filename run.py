import os
import secrets
from pathlib import Path

from flask import Flask
from app.database import initialize_database
from app.database.seed import seed_knowledge_base
from app.environment import load_local_environment
from app.auth import init_auth
from app.routes.auth import auth
from app.routes.dashboard import dashboard
from app.services.poller import start_realtime_poller
from app.services.recommendation_engine import backfill_recommendations
from config import PROJECT_TITLE

load_local_environment()
app = Flask(__name__)
app.config["PROJECT_TITLE"] = PROJECT_TITLE
secret_file = Path(__file__).resolve().parent / "data" / "session.key"
secret_file.parent.mkdir(parents=True, exist_ok=True)
if not secret_file.exists():
    secret_file.write_text(secrets.token_hex(32), encoding="ascii")
app.config.update(
    SECRET_KEY=secret_file.read_text(encoding="ascii").strip(),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_SECURE=False,
    PERMANENT_SESSION_LIFETIME=3600,
    MAX_CONTENT_LENGTH=64 * 1024,
)
init_auth(app)
app.register_blueprint(auth)
app.register_blueprint(dashboard)

# Make sure the local SQLite database is ready whenever the app starts.
initialize_database()
seed_knowledge_base()
with app.app_context():
    from app.database import get_db_connection
    connection = get_db_connection()
    try:
        with connection:
            backfill_recommendations(connection)
    finally:
        connection.close()


@app.after_request
def secure_headers(response):
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; img-src 'self' data:; "
        "script-src 'none'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response

if __name__ == "__main__":
    start_realtime_poller()
    app.run(host="127.0.0.1", port=5000, debug=False, use_reloader=False)
