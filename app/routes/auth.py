"""First-run setup, login/logout, and local user administration."""

import re
import secrets
import sqlite3
import time
import ipaddress
import socket
from datetime import datetime, timedelta, timezone
from time import monotonic
from urllib.parse import urlsplit

from flask import Blueprint, flash, g, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

from app.auth import admin_required, login_required, validate_csrf
from app.database import get_db_connection
from app.services.connectors import CONNECTOR_TYPES, create_connector
from app.services.secret_store import protect_secret, unprotect_secret, SecretProtectionError

auth = Blueprint("auth", __name__)
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
THEMES = {"system", "navy", "high-contrast", "light"}


def _validated_siem_endpoint(raw_url, raw_port, resolve=False):
    parsed = urlsplit(raw_url.strip())
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Use an HTTPS URL without embedded credentials.")
    if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Enter only the SIEM base URL, without a path or query.")
    try:
        port = int(raw_port)
    except (TypeError, ValueError) as error:
        raise ValueError("Port must be a number between 1 and 65535.") from error
    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535.")
    if resolve:
        try:
            addresses = {item[4][0] for item in socket.getaddrinfo(parsed.hostname, port)}
        except socket.gaierror as error:
            raise ValueError("The SIEM hostname could not be resolved.") from error
        for address in addresses:
            ip = ipaddress.ip_address(address)
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
                raise ValueError("Loopback, link-local and multicast SIEM destinations are blocked.")
    return f"https://{parsed.hostname}", port


def _audit_connector(connection, connection_id, action, details):
    connection.execute(
        "INSERT INTO connector_audit (connection_id, actor_user_id, action, details) VALUES (?, ?, ?, ?)",
        (connection_id, g.user["id"], action, details),
    )


def _masked_endpoint(port):
    return f"https://0.0.0.0:{port} (address hidden)"


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
                session["auth_version"] = 1
                session["last_activity"] = int(time.time())
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
                "SELECT id, password_hash, is_active, auth_version FROM users WHERE username = ?",
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
                session["auth_version"] = user["auth_version"]
                session["last_activity"] = int(time.time())
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


@auth.get("/session-expired")
def session_expired():
    session.clear()
    return redirect(url_for("auth.login", expired=1))


@auth.route("/profile", methods=("GET", "POST"))
@login_required
def profile():
    connection = get_db_connection()
    try:
        user = connection.execute(
            "SELECT id, username, password_hash, role, created_at, last_login_at, theme FROM users WHERE id = ?",
            (g.user["id"],),
        ).fetchone()
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action")
            current_password = request.form.get("current_password", "")
            if action == "theme":
                theme = request.form.get("theme", "system")
                if theme not in THEMES:
                    flash("Invalid colour scheme.", "error")
                else:
                    with connection:
                        connection.execute("UPDATE users SET theme = ? WHERE id = ?", (theme, user["id"]))
                    flash("Colour scheme updated.", "success")
                    return redirect(url_for("auth.profile"))
            elif not check_password_hash(user["password_hash"], current_password):
                flash("Current password is incorrect.", "error")
            elif action == "username":
                username = request.form.get("username", "").strip()
                if not USERNAME_RE.fullmatch(username):
                    flash("Username must be 3–32 valid characters.", "error")
                else:
                    try:
                        with connection:
                            connection.execute("UPDATE users SET username = ? WHERE id = ?",
                                               (username, user["id"]))
                        flash("Username updated.", "success")
                        return redirect(url_for("auth.profile"))
                    except sqlite3.IntegrityError:
                        flash("That username already exists.", "error")
            elif action == "password":
                password = request.form.get("password", "")
                confirmation = request.form.get("confirmation", "")
                if password != confirmation:
                    flash("New passwords do not match.", "error")
                elif not _valid_password(password):
                    flash("New password needs 12+ characters, upper/lower-case, and a number.", "error")
                else:
                    with connection:
                        connection.execute("UPDATE users SET password_hash = ?, auth_version = auth_version + 1 WHERE id = ?",
                                           (generate_password_hash(password, method="scrypt"), user["id"]))
                    session["auth_version"] = int(session.get("auth_version", 1)) + 1
                    flash("Password updated.", "success")
                    return redirect(url_for("auth.profile"))
        return render_template("profile.html", profile_user=user)
    finally:
        connection.close()


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
                except sqlite3.IntegrityError:
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
                    "UPDATE users SET is_active = CASE is_active WHEN 1 THEN 0 ELSE 1 END, auth_version = auth_version + 1 WHERE id = ?",
                    (user_id,),
                )
        finally:
            connection.close()
    return redirect(url_for("auth.users"))


@auth.route("/admin/users/<int:user_id>/edit", methods=("GET", "POST"))
@admin_required
def edit_user(user_id):
    connection = get_db_connection()
    try:
        user = connection.execute(
            "SELECT id, username, role, is_active, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
        if not user:
            return redirect(url_for("auth.users"))
        if request.method == "POST":
            validate_csrf()
            username = request.form.get("username", "").strip()
            role = request.form.get("role", "analyst")
            password = request.form.get("password", "")
            error = None
            if not USERNAME_RE.fullmatch(username) or role not in {"admin", "analyst"}:
                error = "Invalid username or role."
            elif user_id == g.user["id"] and role != "admin":
                error = "You cannot remove your own administrator role."
            elif password and not _valid_password(password):
                error = "Reset password needs 12+ characters, upper/lower-case, and a number."
            if error:
                flash(error, "error")
            else:
                try:
                    with connection:
                        connection.execute("UPDATE users SET username = ?, role = ? WHERE id = ?",
                                           (username, role, user_id))
                        if password:
                            connection.execute("UPDATE users SET password_hash = ?, auth_version = auth_version + 1 WHERE id = ?",
                                               (generate_password_hash(password, method="scrypt"), user_id))
                    flash("Account updated.", "success")
                    return redirect(url_for("auth.users"))
                except sqlite3.IntegrityError:
                    flash("That username already exists.", "error")
        return render_template("edit_user.html", edit_user=user)
    finally:
        connection.close()


@auth.route("/admin/security-settings", methods=("GET", "POST"))
@admin_required
def security_settings():
    connection = get_db_connection()
    try:
        if request.method == "POST":
            validate_csrf()
            try:
                timeout = int(request.form.get("session_timeout_minutes", "60"))
            except ValueError:
                timeout = 0
            theme = request.form.get("default_theme", "navy")
            try:
                poll_interval = int(request.form.get("poll_interval_seconds", "30"))
                batch_size = int(request.form.get("poll_batch_size", "100"))
                minimum_level = int(request.form.get("minimum_rule_level", "5"))
                correlation_threshold = int(request.form.get("correlation_threshold", "3"))
            except ValueError:
                poll_interval = batch_size = minimum_level = correlation_threshold = -1
            if not 5 <= timeout <= 480:
                flash("Session timeout must be between 5 and 480 minutes.", "error")
            elif theme not in THEMES - {"system"}:
                flash("Invalid default colour scheme.", "error")
            elif not 10 <= poll_interval <= 3600:
                flash("Poll interval must be between 10 and 3600 seconds.", "error")
            elif not 1 <= batch_size <= 1000:
                flash("Batch size must be between 1 and 1000 events.", "error")
            elif not 0 <= minimum_level <= 16:
                flash("Minimum source rule level must be between 0 and 16.", "error")
            elif not 2 <= correlation_threshold <= 100:
                flash("Correlation threshold must be between 2 and 100 events.", "error")
            else:
                with connection:
                    for key, value in (
                        ("session_timeout_minutes", str(timeout)), ("default_theme", theme),
                        ("poll_interval_seconds", str(poll_interval)),
                        ("poll_batch_size", str(batch_size)),
                        ("minimum_rule_level", str(minimum_level)),
                        ("correlation_threshold", str(correlation_threshold)),
                    ):
                        connection.execute("""UPDATE system_settings SET setting_value = ?, updated_at = CURRENT_TIMESTAMP,
                                              updated_by = ? WHERE setting_key = ?""", (value, g.user["id"], key))
                flash("Security and alert collection settings updated.", "success")
                return redirect(url_for("auth.security_settings"))
        rows = connection.execute("SELECT setting_key, setting_value, updated_at, updated_by FROM system_settings").fetchall()
        settings = {row["setting_key"]: row for row in rows}
        return render_template("security_settings.html", settings=settings)
    finally:
        connection.close()


@auth.route("/admin/siem-connections", methods=("GET", "POST"))
@admin_required
def siem_connections():
    connection = get_db_connection()
    try:
        if request.method == "POST":
            validate_csrf()
            try:
                name = request.form.get("name", "").strip()
                connector_type = request.form.get("connector_type", "")
                base_url, port = _validated_siem_endpoint(request.form.get("base_url", ""), request.form.get("port", "9200"))
                index_pattern = request.form.get("index_pattern", "").strip()
                username = request.form.get("username", "").strip()
                password = request.form.get("password", "")
                if not 3 <= len(name) <= 64:
                    raise ValueError("Connection name must be 3–64 characters.")
                if connector_type not in CONNECTOR_TYPES:
                    raise ValueError("Unsupported SIEM connector type.")
                if not username or len(username) > 128 or not password:
                    raise ValueError("A read-only username and password are required.")
                if not index_pattern or len(index_pattern) > 128:
                    raise ValueError("A valid index pattern is required.")
                encrypted_password = protect_secret(password)
                with connection:
                    cursor = connection.execute("""INSERT INTO siem_connections
                        (name, connector_type, base_url, port, index_pattern, username,
                         encrypted_password, verify_tls, updated_by)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (name, connector_type, base_url, port, index_pattern, username,
                         encrypted_password, int(request.form.get("verify_tls") == "1"), g.user["id"]))
                    _audit_connector(connection, cursor.lastrowid, "created", "SIEM connection created; credential value omitted.")
                flash("SIEM connection saved disabled. Test it before enabling.", "success")
                return redirect(url_for("auth.siem_connections"))
            except (ValueError, sqlite3.IntegrityError, SecretProtectionError) as error:
                flash("That connection name already exists." if isinstance(error, sqlite3.IntegrityError) else str(error), "error")
        rows = connection.execute("""SELECT id, name, connector_type, base_url, port, index_pattern,
                                     username, verify_tls, is_enabled, status, last_success_at,
                                     last_error, response_time_ms, cluster_health, last_alert_at
                              FROM siem_connections ORDER BY name""").fetchall()
        items = [dict(row) | {"display_endpoint": _masked_endpoint(row["port"])} for row in rows]
        return render_template("siem_connections.html", connections=items, connector_types=CONNECTOR_TYPES)
    finally:
        connection.close()


@auth.post("/admin/siem-connections/<int:connection_id>/toggle")
@admin_required
def toggle_siem_connection(connection_id):
    validate_csrf()
    connection = get_db_connection()
    try:
        with connection:
            row = connection.execute("SELECT is_enabled, status FROM siem_connections WHERE id = ?", (connection_id,)).fetchone()
            if not row:
                flash("SIEM connection not found.", "error")
            elif not row["is_enabled"] and row["status"] != "connected":
                flash("Test the connection successfully before enabling it.", "error")
            else:
                enabled = 0 if row["is_enabled"] else 1
                connection.execute("UPDATE siem_connections SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE id = ?", (enabled, g.user["id"], connection_id))
                _audit_connector(connection, connection_id, "enabled" if enabled else "disabled", "Collection state changed; stored history preserved.")
                flash("SIEM collection enabled." if enabled else "SIEM disconnected. Existing history was preserved.", "success")
    finally:
        connection.close()
    return redirect(url_for("auth.siem_connections"))


@auth.post("/admin/siem-connections/<int:connection_id>/test")
@admin_required
def test_siem_connection(connection_id):
    validate_csrf()
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT * FROM siem_connections WHERE id = ?", (connection_id,)).fetchone()
        if not row:
            flash("SIEM connection not found.", "error")
            return redirect(url_for("auth.siem_connections"))
        try:
            base_url, port = _validated_siem_endpoint(row["base_url"], row["port"], resolve=True)
            connector = create_connector(row["connector_type"], base_url=f"{base_url}:{port}",
                username=row["username"], password=unprotect_secret(row["encrypted_password"]),
                index_name=row["index_pattern"], verify_tls=bool(row["verify_tls"]), timeout_seconds=10)
            started = monotonic()
            health = connector.test_connection()
            elapsed = round((monotonic() - started) * 1000)
            cluster_health = str(health.get("status", "available"))[:32]
            with connection:
                connection.execute("""UPDATE siem_connections SET status = 'connected',
                    last_success_at = CURRENT_TIMESTAMP, last_error = NULL, response_time_ms = ?,
                    cluster_health = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?""",
                    (elapsed, cluster_health, connection_id))
                _audit_connector(connection, connection_id, "connection_test_succeeded", f"Health={cluster_health}; response={elapsed}ms.")
            flash(f"Connection successful ({elapsed} ms, cluster {cluster_health}).", "success")
        except Exception as error:
            safe_error = str(error)[:240]
            with connection:
                connection.execute("UPDATE siem_connections SET status = 'error', last_error = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?", (safe_error, connection_id))
                _audit_connector(connection, connection_id, "connection_test_failed", safe_error)
            flash("Connection test failed. Review the health message below.", "error")
    finally:
        connection.close()
    return redirect(url_for("auth.siem_connections"))


@auth.route("/admin/siem-connections/<int:connection_id>/edit", methods=("GET", "POST"))
@admin_required
def edit_siem_connection(connection_id):
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT * FROM siem_connections WHERE id = ?", (connection_id,)).fetchone()
        if not row:
            return redirect(url_for("auth.siem_connections"))
        if request.method == "POST":
            validate_csrf()
            action = request.form.get("action", "details")
            try:
                if action == "password":
                    password = request.form.get("password", "")
                    encrypted = protect_secret(password)
                    with connection:
                        connection.execute("UPDATE siem_connections SET encrypted_password = ?, status = 'not_tested', is_enabled = 0, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE id = ?", (encrypted, g.user["id"], connection_id))
                        _audit_connector(connection, connection_id, "password_replaced", "Credential replaced; value omitted. Connection disabled pending test.")
                    flash("Password replaced. Test the connection before enabling.", "success")
                else:
                    name = request.form.get("name", "").strip()
                    base_url, port = _validated_siem_endpoint(request.form.get("base_url", ""), request.form.get("port", "9200"))
                    index_pattern = request.form.get("index_pattern", "").strip()
                    username = request.form.get("username", "").strip()
                    if not 3 <= len(name) <= 64 or not username or not index_pattern:
                        raise ValueError("Name, index pattern and read-only username are required.")
                    with connection:
                        connection.execute("""UPDATE siem_connections SET name = ?, base_url = ?, port = ?,
                            index_pattern = ?, username = ?, verify_tls = ?, status = 'not_tested',
                            is_enabled = 0, updated_at = CURRENT_TIMESTAMP, updated_by = ? WHERE id = ?""",
                            (name, base_url, port, index_pattern, username,
                             int(request.form.get("verify_tls") == "1"), g.user["id"], connection_id))
                        _audit_connector(connection, connection_id, "edited", "Connection settings changed; credential unchanged. Connection disabled pending test.")
                    flash("Connection updated. Test it before enabling.", "success")
                return redirect(url_for("auth.edit_siem_connection", connection_id=connection_id))
            except (ValueError, sqlite3.IntegrityError, SecretProtectionError) as error:
                flash("That connection name already exists." if isinstance(error, sqlite3.IntegrityError) else str(error), "error")
                row = connection.execute("SELECT * FROM siem_connections WHERE id = ?", (connection_id,)).fetchone()
        return render_template("edit_siem_connection.html", item=row)
    finally:
        connection.close()


@auth.post("/admin/siem-connections/<int:connection_id>/delete")
@admin_required
def delete_siem_connection(connection_id):
    validate_csrf()
    connection = get_db_connection()
    try:
        row = connection.execute("SELECT name, is_enabled FROM siem_connections WHERE id = ?", (connection_id,)).fetchone()
        if not row:
            flash("SIEM connection not found.", "error")
        elif row["is_enabled"]:
            flash("Disconnect the SIEM connection before deleting it.", "error")
        elif request.form.get("confirm_name", "") != row["name"]:
            flash("Deletion confirmation did not match the connection name.", "error")
        else:
            with connection:
                _audit_connector(connection, connection_id, "deleted", "Connection configuration deleted; alert history preserved.")
                connection.execute("DELETE FROM siem_connections WHERE id = ?", (connection_id,))
            flash("SIEM connection deleted. Existing alert history was preserved.", "success")
    finally:
        connection.close()
    return redirect(url_for("auth.siem_connections"))
