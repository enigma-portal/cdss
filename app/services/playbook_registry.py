"""Versioned CDSS investigation methods and deterministic grouped-alert routing.

These definitions describe analyst evidence requests. They do not execute vendor
automations, interpret archive telemetry, or change existing assessment logic.
"""

from dataclasses import dataclass, replace
import re

from app.services.imported_playbooks import imported_playbook


AUTH = 'authentication_review_v1'
FILE_PROCESS = 'file_process_review_v1'
REMOTE_ACCESS = 'remote_access_review_v1'
FALLBACK = 'generic_evidence_review_v1'


@dataclass(frozen=True)
class EvidenceRequest:
    key: str
    label: str
    source_scope: str


@dataclass(frozen=True)
class PlaybookDefinition:
    key: str
    name: str
    family: str
    version: str
    description: str
    provenance: str
    source_ecosystem: str
    source_title: str
    source_url: str
    adaptation_note: str
    help_text: str
    required_pivots: tuple[str, ...]
    optional_pivots: tuple[str, ...]
    evidence_requests: tuple[EvidenceRequest, ...]
    investigation_checks: tuple[str, ...]
    additional_references: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class PlaybookSelection:
    playbook: PlaybookDefinition
    reason: str
    matched_triggers: tuple[str, ...]


ADAPTATION_NOTE = (
    'Investigation concepts adapted for Wazuh/CDSS; vendor-specific automation removed.'
)

PLAYBOOKS = {
    AUTH: PlaybookDefinition(
        AUTH, 'Authentication Investigation', 'authentication', '1',
        'Review account, source and authentication sequence around the grouped detection.',
        'Adapted from open-source playbook guidance', 'Cortex XSOAR public content',
        'Brute Force Investigation - Generic',
        'https://xsoar.pan.dev/docs/reference/playbooks/brute-force-investigation---generic',
        ADAPTATION_NOTE,
        'Reviews reported failures, successes, accounts and sources. A success after failures '
        'does not by itself prove compromise.',
        ('reported_agent_id',), ('username', 'source_ip', 'event_id'),
        (EvidenceRequest('auth_events', 'Authentication failures and successes', 'same-agent archive'),
         EvidenceRequest('account_source', 'Account and source context', 'source alerts / archive'),
         EvidenceRequest('time_sequence', 'Bounded event sequence', 'source alerts / archive')),
        ('Which account and source were reported?', 'Were separate failures observed?',
         'Was a related later success observed?'),
    ),
    FILE_PROCESS: PlaybookDefinition(
        FILE_PROCESS, 'Suspicious File / Process Investigation', 'file_process', '1',
        'Review file, process and adjacent activity without presuming malicious execution.',
        'Adapted from open-source playbook guidance', 'Cortex XSOAR public content; MISP playbooks',
        'Local Analysis alert Investigation; Malware triage',
        'https://xsoar.pan.dev/docs/reference/playbooks/local-analysis-alert-investigation',
        ADAPTATION_NOTE,
        'Reviews file and process context around the detection. It does not confirm malware, '
        'execution or compromise without supporting evidence.',
        ('reported_agent_id',), ('file_path', 'process_name', 'parent_process',
                                 'command_line', 'hashes', 'destination_ip'),
        (EvidenceRequest('file_artifact', 'File path, creation and hashes', 'source alerts / same-agent archive'),
         EvidenceRequest('process_chain', 'Process, parent and command line', 'same-agent archive'),
         EvidenceRequest('related_network', 'Related network activity', 'same-agent archive')),
        ('What artifact or process was actually reported?',
         'Is a parent process or command line available?',
         'Is temporally related network telemetry available?'),
        (('MISP Malware triage playbooks', 'https://github.com/MISP/misp-playbooks'),),
    ),
    REMOTE_ACCESS: PlaybookDefinition(
        REMOTE_ACCESS, 'Remote Access / Lateral Movement Investigation', 'remote_access', '1',
        'Review remote-service and authentication context; do not presume lateral movement.',
        'CDSS-native; CACAO-inspired structure', 'OASIS CACAO; MITRE ATT&CK',
        'CACAO Security Playbooks v2.0; Remote Services (T1021)',
        'https://docs.oasis-open.org/cacao/security-playbooks/v2.0/security-playbooks-v2.0.html',
        'CDSS-native investigation steps; CACAO informs structure only. No CACAO runtime or '
        'vendor automation is executed.',
        'Reviews reported remote service, source, destination and account. Remote access '
        'alone does not establish malicious lateral movement.',
        ('reported_agent_id',), ('source_ip', 'destination_ip', 'username', 'event_id'),
        (EvidenceRequest('remote_service', 'Remote service or logon context', 'source alerts / same-agent archive'),
         EvidenceRequest('remote_entities', 'Source, destination and account', 'source alerts / same-agent archive'),
         EvidenceRequest('cross_host', 'Other involved hosts', 'bounded cross-agent archive query')),
        ('Which remote service and endpoint were reported?',
         'Is an account/source relationship supported?',
         'Is cross-host evidence available for analyst review?'),
        (('MITRE ATT&CK Remote Services (T1021)',
          'https://attack.mitre.org/techniques/T1021/'),),
    ),
    FALLBACK: PlaybookDefinition(
        FALLBACK, 'Generic Evidence Review', 'generic', '1',
        'Present available incident evidence when no dedicated method matches.',
        'Generic fallback', 'CDSS', 'CDSS Generic Evidence Review', '',
        'CDSS-native fallback; no attack-specific interpretation or automation.',
        'Reviews available source evidence only. It does not classify an attack or '
        'infer a missing observation.',
        (), ('reported_agent_id', 'rule_id'),
        (EvidenceRequest('source_evidence', 'Available source and event context',
                         'source alerts / same-agent archive'),),
        ('What is actually present in the alert and bounded archive evidence?',),
    ),
}


def imported_definition(key):
    """Use the verified normalized artifact, not only a provenance label."""
    base=PLAYBOOKS[key]
    if key==FALLBACK:
        return base
    artifact=imported_playbook(key)
    if artifact is None:
        raise ValueError('Required imported playbook is unavailable')
    requests={item.key:item for item in base.evidence_requests}
    if set(requests)!=set(artifact['check_keys']):
        raise ValueError('Imported checks do not match the CDSS evaluator')
    return replace(base,provenance='Hash-pinned imported open-source playbook steps',
        source_ecosystem=artifact['source_ecosystem'],
        source_title=artifact['source_title'],source_url=artifact['source_url'],
        adaptation_note='Only mapped read-only evidence checks run in CDSS; vendor automation is unsupported.',
        evidence_requests=tuple(requests[key] for key in artifact['check_keys']))


def _values(value):
    if isinstance(value, (list, tuple, set, frozenset)):
        return {str(item).strip() for item in value if isinstance(item, (str, int)) and str(item).strip()}
    if isinstance(value, (str, int)) and str(value).strip():
        return {str(value).strip()}
    return set()


def select_playbook(group, pivots):
    """Route only on structured source context; precedence is remote > auth > file.

    Descriptions and arbitrary rule IDs are deliberately not keyword-matched.
    An ATT&CK mapping is used only as existing context, never as a severity score.
    """
    groups = _values(pivots.get('rule_groups'))
    mitre = _values(group.get('mitre_ids'))
    event_ids = _values(pivots.get('event_id'))
    auth_group = bool(groups & {'authentication_failed', 'authentication_success'})
    remote_ids = sorted(value for value in mitre
                        if re.fullmatch(r'T1021(?:\.\d{3})?', value))
    if remote_ids:
        return PlaybookSelection(imported_definition(REMOTE_ACCESS),
            'The grouped detection has existing Remote Services ATT&CK context.',
            tuple(f'MITRE {value}' for value in remote_ids))
    if 'sshd' in groups and auth_group:
        return PlaybookSelection(imported_definition(REMOTE_ACCESS),
            'The source groups identify SSH authentication activity; remote-service review '
            'takes precedence over general authentication review.',
            ('Wazuh group sshd', 'Wazuh authentication group'))
    auth_events = sorted(event_ids & {'4624', '4625', '4771'}) if 'windows_security' in groups else []
    if auth_group or auth_events:
        triggers = sorted(groups & {'authentication_failed', 'authentication_success'})
        triggers += [f'Windows Security Event {value}' for value in auth_events]
        return PlaybookSelection(imported_definition(AUTH),
            'Structured authentication group or Windows Security event context matched.',
            tuple(triggers))
    file_groups = sorted(groups & {'sysmon_eid1_detections', 'sysmon_eid11_detections'})
    if 'syscheck_entry_added' in groups and pivots.get('file_path'):
        file_groups.append('syscheck_entry_added with reported path')
    sysmon_events = sorted(event_ids & {'1', '11'}) if 'sysmon' in groups else []
    file_context = bool(pivots.get('file_path') or pivots.get('process_name'))
    file_mitre = sorted(value for value in mitre if value == 'T1105' or
                        re.fullmatch(r'T1059(?:\.\d{3})?', value)) if file_context else []
    if file_groups or sysmon_events or file_mitre:
        triggers = file_groups + [f'Sysmon Event {value}' for value in sysmon_events]
        triggers += [f'MITRE {value} with file/process context' for value in file_mitre]
        return PlaybookSelection(imported_definition(FILE_PROCESS),
            'Structured file or process telemetry matched the investigation method.',
            tuple(triggers))
    return PlaybookSelection(PLAYBOOKS[FALLBACK],
        'No dedicated playbook matched the structured detection context. '
        'Generic Evidence Review selected.', ())


def evidence_status(*, observed=False, coverage_confirmed=False):
    """Missing telemetry is unavailable, not a negative observation."""
    if observed:
        return 'observed'
    return 'not_observed' if coverage_confirmed else 'unavailable'
