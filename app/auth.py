"""Session authentication, authorization, and CSRF helpers."""

import hmac
import secrets
from functools import wraps

from flask import abort, g, redirect, request, session, url_for

from app.database import get_db_connection


def init_auth(app):
    @app.before_request
    def load_user():
        g.user = None
        user_id = session.get("user_id")
        if user_id is None:
            return
        connection = get_db_connection()
        try:
            user = connection.execute(
                "SELECT id, username, role, is_active FROM users WHERE id = ?",
                (user_id,),
            ).fetchone()
            if user and user["is_active"]:
                g.user = user
            else:
                session.clear()
        finally:
            connection.close()

    @app.context_processor
    def auth_context():
        return {"current_user": g.get("user"), "csrf_token": csrf_token}


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
