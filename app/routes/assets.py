"""Administrator-managed lightweight asset inventory."""

import sqlite3

from flask import Blueprint, abort, flash, redirect, render_template, request, url_for

from app.auth import admin_required, validate_csrf
from app.database import get_db_connection
from app.services.asset_resolver import backfill_asset_links
from app.services.asset_validation import ASSET_CATALOGUE, CRITICALITIES, validate_asset

assets = Blueprint("assets", __name__)


@assets.route("/admin/assets", methods=("GET", "POST"))
@admin_required
def index():
    connection = get_db_connection()
    try:
        if request.method == "POST":
            validate_csrf()
            try:
                data = validate_asset(request.form)
                with connection:
                    cursor = connection.execute("""
                        INSERT INTO assets
                            (asset_name, asset_type, asset_role, os_family, os_name,
                             ip_address, wazuh_agent_id, criticality, is_protected, description)
                        VALUES (:asset_name, :asset_type, :asset_role, :os_family, :os_name,
                                :ip_address, :wazuh_agent_id, :criticality, :is_protected, :description)
                    """, data)
                    backfill_asset_links(connection, cursor.lastrowid, data["wazuh_agent_id"])
                flash("Asset created and exact agent-ID history linked.", "success")
                return redirect(url_for("assets.index"))
            except ValueError as error:
                flash(str(error), "error")
            except sqlite3.IntegrityError:
                flash("That non-empty Wazuh agent ID is already assigned to another asset.", "error")
        rows = connection.execute("""
            SELECT assets.*,
                   (SELECT COUNT(*) FROM alerts WHERE alerts.asset_id = assets.id) AS alert_count
              FROM assets ORDER BY asset_name COLLATE NOCASE, id
        """).fetchall()
        return render_template("assets.html", assets=rows, catalogue=ASSET_CATALOGUE,
                               criticalities=CRITICALITIES)
    finally:
        connection.close()


@assets.route("/admin/assets/<int:asset_id>/edit", methods=("GET", "POST"))
@admin_required
def edit(asset_id):
    connection = get_db_connection()
    try:
        asset = connection.execute("SELECT * FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not asset:
            abort(404)
        if request.method == "POST":
            validate_csrf()
            try:
                data = validate_asset(request.form)
                data["id"] = asset_id
                with connection:
                    connection.execute("""
                        UPDATE assets SET asset_name=:asset_name, asset_type=:asset_type,
                            asset_role=:asset_role, os_family=:os_family, os_name=:os_name,
                            ip_address=:ip_address, wazuh_agent_id=:wazuh_agent_id,
                            criticality=:criticality, is_protected=:is_protected,
                            description=:description, updated_at=CURRENT_TIMESTAMP WHERE id=:id
                    """, data)
                    backfill_asset_links(connection, asset_id, data["wazuh_agent_id"])
                flash("Asset updated.", "success")
                return redirect(url_for("assets.index"))
            except ValueError as error:
                flash(str(error), "error")
            except sqlite3.IntegrityError:
                flash("That non-empty Wazuh agent ID is already assigned to another asset.", "error")
        return render_template("edit_asset.html", asset=asset, catalogue=ASSET_CATALOGUE,
                               criticalities=CRITICALITIES)
    finally:
        connection.close()


@assets.post("/admin/assets/<int:asset_id>/delete")
@admin_required
def delete(asset_id):
    validate_csrf()
    connection = get_db_connection()
    try:
        asset = connection.execute("SELECT asset_name FROM assets WHERE id = ?", (asset_id,)).fetchone()
        if not asset:
            abort(404)
        if request.form.get("confirmation", "") != asset["asset_name"]:
            flash("Enter the exact asset name to confirm deletion.", "error")
            return redirect(url_for("assets.edit", asset_id=asset_id))
        with connection:
            connection.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
        flash("Asset deleted; linked alerts and incidents are now unmapped.", "success")
        return redirect(url_for("assets.index"))
    finally:
        connection.close()
