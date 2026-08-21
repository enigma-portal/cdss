"""Session authentication, authorization, and CSRF helpers."""

import hmac
import secrets
import time
from functools import wraps

from flask import abort, g, redirect, request, session, url_for

from app.database import get_db_connection


def init_auth(app):
    @app.before_request
    def load_user():
        g.user = None
        connection = get_db_connection()
        try:
            settings = dict(connection.execute(
                "SELECT setting_key, setting_value FROM system_settings"
            ).fetchall())
            g.siem_monitoring_active = connection.execute(
                "SELECT 1 FROM siem_connections WHERE is_enabled = 1 LIMIT 1"
            ).fetchone() is not None
        finally:
            connection.close()
        try:
            timeout_minutes = max(5, min(480, int(settings.get("session_timeout_minutes", "60"))))
        except ValueError:
            timeout_minutes = 60
        g.session_timeout_seconds = timeout_minutes * 60
        g.default_theme = settings.get("default_theme", "navy")
        user_id = session.get("user_id")
        if user_id is None:
            return
        now = int(time.time())
        if now - int(session.get("last_activity", now)) > g.session_timeout_seconds:
            session.clear()
            return redirect(url_for("auth.login", expired=1))
        connection = get_db_connection()
        try:
            user = connection.execute(
                "SELECT id, username, role, is_active, theme, auth_version FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if user and "auth_version" not in session:
                # Upgrade sessions created before auth-version enforcement;
                # subsequent password resets or disables still invalidate them.
                session["auth_version"] = user["auth_version"]
            if (user and user["is_active"] and
                    int(session.get("auth_version", -1)) == user["auth_version"]):
                g.user = user
                session["last_activity"] = now
            else:
                session.clear()
        finally:
            connection.close()

    @app.context_processor
    def auth_context():
        user = g.get("user")
        selected = user["theme"] if user and user["theme"] != "system" else g.get("default_theme", "navy")
        return {"current_user": user, "csrf_token": csrf_token,
                "effective_theme": selected,
                "siem_monitoring_active": g.get("siem_monitoring_active", False),
                "session_timeout_seconds": g.get("session_timeout_seconds", 3600)}


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf():
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token", "")
    if not expected or not supplied or not hmac.compare_digest(expected, supplied):
        abort(400, "Invalid form token. Refresh the page and try again.")


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login", next=request.full_path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapped(*args, **kwargs):
        if g.user["role"] != "admin":
            abort(403)
        return view(*args, **kwargs)
    return wrapped
