"""Versioned, project-defined grouped-alert triage; never a final risk verdict.

Wazuh permits rule levels 0–16; level 0 is ignored and does not produce a
stored alert. The supported alert bands here are 1–4 Low, 5–7 Medium, 8–11
High, and 12–16 Critical. These bands are CDSS triage choices, not Wazuh's
official priority labels.

The administrator's four criticality levels shift the raw Wazuh level by
-2/-1/0/+1 *before* banding. This distinguishes every adjacent criticality
near a band boundary while keeping detection severity primary. Critical
priority requires source level >=12; asset importance alone cannot create it.

One additional tier applies if EITHER (a) a source-provided ATT&CK ID resolves
to the official local catalogue and Wazuh level >=5, OR (b) at least three
distinct stored events occur within the configured grouped-alert window.
Both conditions together still add only one tier. The recurrence count is
capped at five; rule.firedtimes is never used. An ATT&CK mapping adds
investigation context, not a technique severity or proof of maliciousness.
Missing mapping never penalizes the base tier. The post-investigation
contextual risk engine does not read this model.
"""

from dataclasses import dataclass
import re


VERSION = 'cdss-initial-priority-v2'
LABELS = ('Low', 'Medium', 'High', 'Critical')
ASSET_LEVEL_ADJUSTMENT = {'low': -2, 'medium': -1, 'high': 0, 'critical': 1}
CRITICAL_SOURCE_MIN_LEVEL = 12
MITRE_SOURCE_MIN_LEVEL = 5
TECHNIQUE_ID = re.compile(r'T[0-9]{4}(?:\.[0-9]{3})?\Z')
RECURRENCE_THRESHOLD = 3
RECURRENCE_COUNT_CAP = 5
MAX_TOTAL_MODIFIER = 1


@dataclass(frozen=True)
class InitialPriority:
    level: str | None
    rationale: str
    model_version: str = VERSION
    severity_tier: str | None = None
    asset_criticality: str | None = None
    mitre_modifier: int = 0
    recurrence_modifier: int = 0
    occurrence_count_used: int = 0


def _severity_tier(level):
    if type(level) is not int or not 1 <= level <= 16:
        return None
    if level <= 4:
        return 0
    if level <= 7:
        return 1
    if level <= 11:
        return 2
    return 3


def priority_rank(source_level, criticality, occurrences, official_mapping):
    """Pure priority tier shared by the detail calculation and SQL queue sort."""
    if _severity_tier(source_level) is None or criticality not in ASSET_LEVEL_ADJUSTMENT:
        return None
    try:
        count = min(max(0, int(occurrences)), RECURRENCE_COUNT_CAP)
    except (TypeError, ValueError):
        count = 0
    adjusted_level = max(1, min(16, source_level + ASSET_LEVEL_ADJUSTMENT[criticality]))
    base = _severity_tier(adjusted_level)
    modifier = int(bool((official_mapping and source_level >= MITRE_SOURCE_MIN_LEVEL)
                        or count >= RECURRENCE_THRESHOLD))
    result = min(3, base + min(MAX_TOTAL_MODIFIER, modifier))
    return min(result, 2) if source_level < CRITICAL_SOURCE_MIN_LEVEL else result


def calculate_initial_priority(group, connection):
    """Prioritize one already-windowed, equivalent grouped alert.

    This never reads legacy knowledge_base.base_risk_score. Only normalized
    Wazuh-source IDs with official local catalogue metadata qualify as ATT&CK
    context. The caller supplies actual stored group-member count, not
    Wazuh rule.firedtimes.
    """
    source_level = group.get('rule_level')
    severity = _severity_tier(source_level)
    criticality = group.get('criticality')
    count = min(max(0, int(group.get('occurrences') or 0)), RECURRENCE_COUNT_CAP)
    if severity is None:
        return InitialPriority(None, 'Wazuh detection level is unavailable; initial priority is not assigned.',
                               asset_criticality=criticality, occurrence_count_used=count)
    if criticality not in ASSET_LEVEL_ADJUSTMENT:
        return InitialPriority(None, 'Administrator-defined asset criticality is unavailable; initial priority is not assigned.',
                               severity_tier=LABELS[severity], occurrence_count_used=count)
    source_ids = group.get('wazuh_mitre_ids')
    techniques = sorted({item for item in source_ids
                         if isinstance(item, str) and TECHNIQUE_ID.fullmatch(item)}) \
        if isinstance(source_ids, (list, tuple, set)) else []
    official_mapping = False
    if source_level >= MITRE_SOURCE_MIN_LEVEL and techniques:
        placeholders = ','.join('?' for _ in techniques)
        official_mapping = connection.execute(
            f"SELECT 1 FROM mitre_techniques WHERE catalogue_source='taxii' "
            f'AND technique_id IN ({placeholders}) LIMIT 1', techniques).fetchone() is not None
    mitre_modifier = int(official_mapping)
    recurrence_modifier = int(count >= RECURRENCE_THRESHOLD)
    # EITHER eligible context raises by one tier; BOTH still raise by one.
    adjustment = min(MAX_TOTAL_MODIFIER, int(bool(mitre_modifier or recurrence_modifier)))
    result = priority_rank(source_level, criticality, count, official_mapping)
    reasons = [f'Wazuh level {source_level} is {LABELS[severity]} detection context',
               f'administrator asset criticality {criticality} adjusts the level by '
               f'{ASSET_LEVEL_ADJUSTMENT[criticality]:+d} before banding',
               f'{count} stored occurrence(s) in the {group["group_window_minutes"]}-minute group']
    if mitre_modifier:
        reasons.append('a source-provided ATT&CK ID resolves to the official local catalogue')
    if adjustment:
        reasons.append('eligible ATT&CK context or recurrence raises priority by one tier, even if both apply')
    if source_level < CRITICAL_SOURCE_MIN_LEVEL:
        reasons.append('Critical is reserved for Wazuh source level 12 or above')
    return InitialPriority(LABELS[result], '; '.join(reasons) + '.', severity_tier=LABELS[severity],
                           asset_criticality=criticality, mitre_modifier=mitre_modifier,
                           recurrence_modifier=recurrence_modifier, occurrence_count_used=count)
