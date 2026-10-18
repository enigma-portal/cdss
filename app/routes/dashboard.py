"""Dashboard reads and explicit, CSRF-protected evidence investigation execution."""


from flask import Blueprint, abort, render_template, request, redirect, url_for, flash, current_app, g

from app.database import get_db_connection
from app.auth import login_required, validate_csrf
from app.services.investigation import run_investigation, investigation_history
from app.services.contextual_risk import (
    assess_investigation, create_initial_assessment, assessment_history, current_assessment,
)
from app.services.contextual_recommendations import (
    generate_contextual_recommendations, record_analyst_decision, recommendation_history, decision_history,
)

from app.services.dashboard_context import (
    overview_data, list_data, incident_evidence, assessment_notices, incident_presentation,
    recommendation_presentation, audit_presentation,
)
from app.services.alert_view import alert_detail_data, group_context, list_alerts, source_label
from app.services.archive_evidence import (
    archive_run_detail, archive_runs_for_case, start_group_archive_retrieval,
)

dashboard = Blueprint("dashboard", __name__)
@dashboard.route("/")
@login_required
def index():
    return render_template("overview.html", overview=overview_data())


@dashboard.route("/alerts")
@login_required
def alerts():
    connection = get_db_connection()
    try:
        items, pagination = list_alerts(connection, request.args)
        return render_template("alerts.html", alerts=items, pagination=pagination)
    finally:
        connection.close()


@dashboard.route("/alerts/<int:alert_id>")
@login_required
def alert_detail(alert_id):
    connection = get_db_connection()
    try:
        alert = alert_detail_data(connection, alert_id)
        if alert is None:
            abort(404)
        return render_template("alert_detail.html", alert=alert)
    finally:
        connection.close()


@dashboard.route("/alerts/groups/<int:alert_id>")
@login_required
def alert_group_detail(alert_id):
    connection = get_db_connection()
    try:
        group = group_context(connection, alert_id)
        if group is None:
            abort(404)
        return render_template("alert_group_detail.html", group=group)
    finally:
        connection.close()


@dashboard.route("/alerts/groups/<int:alert_id>/investigate", methods=["POST"])
@login_required
def investigate_group(alert_id):
    validate_csrf()
    connection = get_db_connection()
    try:
        group = group_context(connection, alert_id)
        if group is None:
            abort(404)
        if group['active_case_id']:
            return redirect(url_for('dashboard.incident_detail',incident_id=group['active_case_id']))
    finally:
        connection.close()
    try:
        execution_id = start_group_archive_retrieval(alert_id)
    except LookupError:
        abort(404)
    except Exception:
        current_app.logger.error("Grouped archive retrieval setup failed")
        flash("Investigation could not be started. No evidence was invented.", "error")
        return redirect(url_for('dashboard.alert_group_detail', alert_id=alert_id))
    connection = get_db_connection()
    try:
        row = connection.execute('SELECT incident_id FROM investigations WHERE id=?',
                                 (execution_id,)).fetchone()
        if row is None:
            raise LookupError('Investigation case unavailable')
        incident_id = row['incident_id']
    finally:
        connection.close()
    try:
        run_id = run_investigation(incident_id)
        assess_investigation(incident_id,run_id)
        _generate_guidance(incident_id)
    except Exception:
        current_app.logger.error('Grouped investigation pipeline failed for case %s',incident_id)
        flash('The case is saved, but evidence evaluation did not complete. Re-run investigation from the case.', 'error')
    return redirect(url_for('dashboard.incident_detail',incident_id=incident_id))


@dashboard.route("/investigations/archive/<int:execution_id>")
@login_required
def archive_evidence_detail(execution_id):
    connection = get_db_connection()
    try:
        evidence_run = archive_run_detail(connection, execution_id)
        if evidence_run is None:
            abort(404)
        return render_template("archive_evidence_detail.html", run=evidence_run)
    finally:
        connection.close()


@dashboard.route("/incidents")
@login_required
def incidents():
    totals, incidents, pagination = list_data(request.args)
    return render_template("dashboard.html", totals=totals, incidents=incidents,
                           pagination=pagination, filter_values={key:pagination[key] for key in ('q','severity','status','criticality','evidence','decision','confidence','view')})


@dashboard.route("/incidents/<int:incident_id>")
@login_required
def incident_detail(incident_id):
    connection = get_db_connection()
    try:
        incident = connection.execute("""
            SELECT incidents.*, alerts.wazuh_alert_id, alerts.event_timestamp,
                   alerts.rule_id, alerts.rule_description, alerts.rule_level, alerts.rule_groups,
                   alerts.agent_id, alerts.agent_name, alerts.agent_ip,
                   alerts.source_ip, alerts.destination_ip, alerts.processing_status
            FROM incidents JOIN alerts ON alerts.id = incidents.alert_id
            WHERE incidents.id = ?
        """, (incident_id,)).fetchone()
        if not incident:
            abort(404)
        asset_row=connection.execute('SELECT a.* FROM assets a JOIN incidents i ON i.asset_id=a.id WHERE i.id=?',(incident_id,)).fetchone()
        timeline=incident_evidence(connection,incident_id)
        from app.services.mitre_mapping import get_incident_mitre_context
        techniques = get_incident_mitre_context(connection, incident_id)["techniques"]
        guidance=recommendation_history(connection,incident_id)
        decisions=decision_history(connection,incident_id)
        contextual=current_assessment(connection,incident_id)
        investigations=investigation_history(connection, incident_id)
        archive_runs=archive_runs_for_case(connection, incident_id)
        # The evidence beside an assessment must be from the retrieval available
        # when that assessed investigation ran, not a later failed/retried run.
        relevant_archive=next((run for run in archive_runs
            if contextual is None or run['investigation_id'] < contextual['investigation_id']),None)
        latest_archive=(archive_run_detail(connection,relevant_archive['investigation_id'])
                        if relevant_archive else None)
        initial_priority=connection.execute('''SELECT * FROM initial_alert_priorities
            WHERE incident_id=?''',(incident_id,)).fetchone()
        audit=audit_presentation(timeline,techniques,investigations)
        asset=dict(asset_row) if asset_row else None
        current_guidance=[item for item in guidance if contextual and item['assessment_id']==contextual['id']]
        if current_guidance:
            latest_version=max(current_guidance,key=lambda item:item['id'])['methodology_version']
            current_guidance=[item for item in current_guidance if item['methodology_version']==latest_version]
        assessed_investigation=next((run for run in investigations if contextual and
            run['id']==contextual['investigation_id']),None)
        from app.services.playbook_registry import PLAYBOOKS, imported_definition
        from app.services.imported_playbooks import imported_playbook
        playbook_key=assessed_investigation['playbook_key'] if assessed_investigation else None
        saved_artifact=(imported_playbook(playbook_key) if playbook_key in PLAYBOOKS else None)
        playbook_source_verified=bool(saved_artifact and assessed_investigation['playbook_import_hash']
            == saved_artifact['source_sha256'])
        selected_playbook=(imported_definition(playbook_key) if playbook_source_verified else
            PLAYBOOKS.get(playbook_key))
        check_findings=([] if not assessed_investigation else [finding for finding in assessed_investigation['findings']
            if finding['finding_key'] not in ('linked_alert_evidence','asset_context','mitre_context',
                                              'no_specific_playbook')])
        check_counts={status:sum(finding['finding_status']==status for finding in check_findings)
            for status in ('observed','not_observed','unavailable')}
        check_counts['total']=len(check_findings)
        selected_playbook_reason=(latest_archive['selection_reason']
            if selected_playbook and latest_archive and
               latest_archive['selected_playbook_key']==selected_playbook.key else None)
        current_decision=next((d for d in decisions if contextual and
            d['assessment_id']==contextual['id'] and d['incident_recommendation_id'] is None),None)
        if current_decision is None:
            current_decision=next((d for d in decisions if contextual and
                d['assessment_id']==contextual['id']),None)
        for item in current_guidance:
            item.update(recommendation_presentation(item,asset,timeline,contextual,assessed_investigation))
        notices=assessment_notices(connection,incident_id,contextual,asset_row)
        presentation=incident_presentation(dict(incident),asset,timeline,investigations,contextual,notices)
        return render_template("incident_detail.html", incident=dict(incident),
                               reported_system=source_label(incident['agent_id'], incident['agent_name']),
                               techniques=techniques, asset=asset, timeline=timeline,
                               investigations=investigations, presentation=presentation, audit=audit,
                               archive_runs=archive_runs,
                               latest_archive=latest_archive,selected_playbook=selected_playbook,
                               assessed_investigation=assessed_investigation,
                               playbook_source_verified=playbook_source_verified,
                               check_counts=check_counts,
                               selected_playbook_reason=selected_playbook_reason,
                               initial_priority=dict(initial_priority) if initial_priority else None,
                               assessments=assessment_history(connection, incident_id),
                               contextual=contextual, current_guidance=current_guidance,
                               assessment_notices=notices, decisions=decisions,
                               current_decision=current_decision)
    finally:
        connection.close()


@dashboard.route("/incidents/<int:incident_id>/investigations", methods=["POST"])
@login_required
def investigate(incident_id):
    validate_csrf()
    try:
        connection = get_db_connection()
        try:
            case = connection.execute('''SELECT case_origin,group_anchor_alert_id
                FROM incidents WHERE id=?''',(incident_id,)).fetchone()
        finally:
            connection.close()
        if case is None:
            raise LookupError('Investigation case not found')
        # A deliberate re-run of a grouped case refreshes bounded archive
        # evidence before the findings and assessment are recalculated.
        if case['case_origin'] == 'analyst_group' and case['group_anchor_alert_id']:
            connection = get_db_connection()
            try:
                prior_assessment = current_assessment(connection,incident_id)
            finally:
                connection.close()
            retrieval_id = start_group_archive_retrieval(case['group_anchor_alert_id'])
            if prior_assessment:
                connection = get_db_connection()
                try:
                    retrieval = connection.execute('''SELECT retrieval_status FROM investigation_archive_runs
                        WHERE investigation_id=?''',(retrieval_id,)).fetchone()
                finally:
                    connection.close()
                if retrieval is None or retrieval['retrieval_status'] not in ('available','empty'):
                    flash('Latest evidence retrieval unavailable. Last successful assessment remains current.', 'error')
                    return redirect(url_for('dashboard.incident_detail', incident_id=incident_id,
                        _anchor='contextual-assessment'))
        execution_id = run_investigation(incident_id)
    except LookupError:
        abort(404)
    except Exception:
        # Neither raw evidence nor exception strings belong in the UI/log output.
        current_app.logger.error("Investigation execution failed for incident %s", incident_id)
        flash("Investigation failed. No partial findings were saved; you may retry.", "error")
    else:
        try:
            assess_investigation(incident_id, execution_id)
        except Exception:
            current_app.logger.error("Contextual assessment failed for incident %s", incident_id)
            flash("Investigation saved, but assessment failed. Use Assess this execution to retry.", "error")
        else:
            _generate_guidance(incident_id)
    return redirect(url_for('dashboard.incident_detail', incident_id=incident_id, _anchor='investigation'))


@dashboard.route("/incidents/<int:incident_id>/assessments/initial", methods=["POST"])
@login_required
def initial_assessment(incident_id):
    validate_csrf()
    try:
        create_initial_assessment(incident_id)
    except LookupError:
        abort(404)
    except Exception:
        current_app.logger.error("Initial assessment failed for incident %s", incident_id)
        flash("Initial assessment could not be saved.", "error")
    return redirect(url_for('dashboard.incident_detail', incident_id=incident_id, _anchor='contextual-assessment'))


@dashboard.route("/incidents/<int:incident_id>/assessments/<int:investigation_id>", methods=["POST"])
@login_required
def contextual_assessment(incident_id, investigation_id):
    validate_csrf()
    try:
        assess_investigation(incident_id, investigation_id)
    except LookupError:
        abort(404)
    except ValueError:
        abort(409, 'A completed investigation is required.')
    except Exception:
        current_app.logger.error("Contextual assessment failed for incident %s", incident_id)
        flash("Contextual assessment could not be saved.", "error")
    else:
        _generate_guidance(incident_id)
    return redirect(url_for('dashboard.incident_detail', incident_id=incident_id, _anchor='contextual-assessment'))


def _generate_guidance(incident_id):
    try:
        generate_contextual_recommendations(incident_id)
    except Exception:
        current_app.logger.error('Contextual guidance generation failed for incident %s',incident_id)
        flash('Assessment preserved. Guidance could not be generated; use Generate current guidance to retry.', 'error')


@dashboard.route('/incidents/<int:incident_id>/recommendations',methods=['POST'])
@login_required
def generate_guidance(incident_id):
    validate_csrf()
    _generate_guidance(incident_id)
    return redirect(url_for('dashboard.incident_detail',incident_id=incident_id,_anchor='contextual-guidance'))


@dashboard.route('/incidents/<int:incident_id>/analyst-decisions',methods=['POST'])
@login_required
def analyst_decision(incident_id):
    validate_csrf()
    if g.user['role'] not in ('admin','analyst'):
        abort(403)
    try:
        assessment_id=int(request.form.get('assessment_id',''))
        recommendation_value=request.form.get('recommendation_id','')
        recommendation_id=int(recommendation_value) if recommendation_value else None
        record_analyst_decision(incident_id,assessment_id,recommendation_id,g.user['id'],
            request.form.get('decision',''),request.form.get('comments',''))
    except ValueError as error:
        abort(400, str(error) if str(error).startswith(('Select','Comments','Assessment')) else 'Invalid decision reference')
    except PermissionError:
        abort(403)
    except LookupError:
        abort(404)
    except Exception:
        current_app.logger.error('Analyst decision could not be saved for incident %s',incident_id)
        flash('Decision could not be saved. No response action was executed.','error')
    else:
        flash('Analyst decision recorded. No response action was executed.','success')
    return redirect(url_for('dashboard.incident_detail',incident_id=incident_id,_anchor='analyst-decision'))


@dashboard.route("/health")
def health():
    connection = get_db_connection()
    try:
        connection.execute("SELECT 1").fetchone()
        return {"status": "ok"}
    finally:
        connection.close()
