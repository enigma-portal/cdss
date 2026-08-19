"""First-run setup, login/logout, and local user administration."""

import re
import secrets
from datetime import datetime, timedelta, timezone
from urllib.parse import urlsplit

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.auth import admin_required, validate_csrf
from app.database import get_db_connection

auth = Blueprint("auth", __name__)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")


def _users_exist(connection):
    return connection.execute("SELECT 1 FROM users LIMIT 1").fetchone() is not None


def _valid_password(password):
    return (len(password) >= 12 and any(c.islower() for c in password)
            and any(c.isupper() for c in password) and any(c.isdigit() for c in password))


def _safe_next(value):
    if not value:
        return url_for("dashboard.index")
    parsed = urlsplit(value)
    return value if not parsed.scheme and not parsed.netloc and value.startswith("/") else url_for("dashboard.index")


@auth.route("/setup", methods=("GET", "POST"))
def setup():
    connection = get_db_connection()
    try:
        if _users_exist(connection):
            return redirect(url_for("auth.login"))
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            confirmation = request.form.get("confirmation", "")
            error = None
            if not USERNAME_RE.fullmatch(username):
                error = "Username must be 3–32 letters, numbers, dots, dashes, or underscores."
            elif password != confirmation:
                error = "Passwords do not match."
            elif not _valid_password(password):
                error = "Use at least 12 characters with upper-case, lower-case, and a number."
            if error:
                flash(error, "error")
            else:
                with connection:
                    cursor = connection.execute(
                        "INSERT INTO users (username, password_hash, role) VALUES (?, ?, 'admin')",
                        (username, generate_password_hash(password, method="scrypt")),
                    )
                session.clear()
                session["user_id"] = cursor.lastrowid
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(url_for("dashboard.index"))
        return render_template("setup.html")
    finally:
        connection.close()


@auth.route("/login", methods=("GET", "POST"))
def login():
    connection = get_db_connection()
    try:
        if not _users_exist(connection):
            return redirect(url_for("auth.setup"))
        if g.user:
            return redirect(url_for("dashboard.index"))
        if request.method == "POST":
            validate_csrf()
            locked_until = session.get("login_locked_until")
            now = datetime.now(timezone.utc)
            if locked_until and now < datetime.fromisoformat(locked_until):
                flash("Too many attempts. Wait one minute and try again.", "error")
                return render_template("login.html"), 429
            username = request.form.get("username", "").strip()[:32]
            password = request.form.get("password", "")
            user = connection.execute(
                "SELECT id, password_hash, is_active FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            if not user or not user["is_active"] or not check_password_hash(user["password_hash"], password):
                attempts = int(session.get("login_attempts", 0)) + 1
                session["login_attempts"] = attempts
                if attempts >= 5:
                    session["login_locked_until"] = (now + timedelta(minutes=1)).isoformat()
                    session["login_attempts"] = 0
                flash("Invalid username or password.", "error")
            else:
                with connection:
                    connection.execute(
                        "UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = ?", (user["id"],)
                    )
                session.clear()
                session["user_id"] = user["id"]
                session["csrf_token"] = secrets.token_urlsafe(32)
                return redirect(_safe_next(request.args.get("next")))
        return render_template("login.html")
    finally:
        connection.close()


@auth.post("/logout")
def logout():
    validate_csrf()
    session.clear()
    return redirect(url_for("auth.login"))


@auth.route("/admin/users", methods=("GET", "POST"))
@admin_required
def users():
    connection = get_db_connection()
    try:
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "")
            role = request.form.get("role", "analyst")
            if not USERNAME_RE.fullmatch(username) or role not in {"admin", "analyst"}:
                flash("Invalid username or role.", "error")
            elif not _valid_password(password):
                flash("Password needs 12+ characters, upper/lower-case, and a number.", "error")
            else:
                try:
                    with connection:
                        connection.execute(
                            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                            (username, generate_password_hash(password, method="scrypt"), role),
                        )
                    flash("User account created.", "success")
                except Exception as error:
                    if "UNIQUE constraint" not in str(error):
                        raise
                    flash("That username already exists.", "error")
        rows = connection.execute(
            "SELECT id, username, role, is_active, created_at, last_login_at FROM users ORDER BY username"
        ).fetchall()
        return render_template("users.html", users=rows)
    finally:
        connection.close()


@auth.post("/admin/users/<int:user_id>/toggle")
@admin_required
def toggle_user(user_id):
    validate_csrf()
    if user_id == g.user["id"]:
        flash("You cannot deactivate your own account.", "error")
    else:
        connection = get_db_connection()
        try:
            with connection:
                connection.execute(
                    "UPDATE users SET is_active = CASE is_active WHEN 1 THEN 0 ELSE 1 END WHERE id = ?",
                    (user_id,),
                )
        finally:
            connection.close()
    return redirect(url_for("auth.users"))
