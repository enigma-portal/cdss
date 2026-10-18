"""Read-only adapter for curated, hash-pinned public playbook source steps.

Only allowlisted investigative checks are mapped. XSOAR automation commands
are retained as unsupported provenance and are never executed by CDSS.
"""

from functools import lru_cache
import hashlib
import json
from pathlib import Path
import re


MANIFEST = Path(__file__).resolve().parents[1] / 'playbooks' / 'imported_manifest.json'
EXPECTED_CHECKS = {
    'authentication_review_v1': frozenset(('auth_events','account_source','time_sequence')),
    'file_process_review_v1': frozenset(('file_artifact','process_chain','related_network')),
    'remote_access_review_v1': frozenset(('remote_service','remote_entities','cross_host')),
}


@lru_cache(maxsize=1)
def load_imported_playbooks():
    data=json.loads(MANIFEST.read_text(encoding='utf-8'))
    if data.get('schema_version')!='cdss-playbook-import-v1':
        raise ValueError('Unsupported imported playbook manifest version')
    artifacts=data.get('artifacts')
    if not isinstance(artifacts,dict) or set(artifacts)!=set(EXPECTED_CHECKS):
        raise ValueError('Imported playbook catalogue is incomplete')
    for key,artifact in artifacts.items():
        if (not isinstance(artifact,dict) or
                not re.fullmatch(r'[0-9a-f]{64}',artifact.get('source_sha256','')) or
                artifact.get('source_ecosystem')!='Cortex XSOAR public content' or
                not artifact.get('source_path','').endswith('.yml') or
                set(artifact.get('check_keys',[]))!=EXPECTED_CHECKS[key]):
            raise ValueError('Imported playbook metadata is invalid')
        steps=artifact.get('steps')
        if not isinstance(steps,list) or not steps:
            raise ValueError('Imported playbook has no source steps')
        names=set()
        for step in steps:
            if not isinstance(step,dict) or not isinstance(step.get('source_step'),str):
                raise ValueError('Imported source step is invalid')
            if step['source_step'] in names or not isinstance(step.get('supported'),bool):
                raise ValueError('Imported source step is duplicated or unsupported')
            names.add(step['source_step'])
            if bool(step.get('mapped_implementation')) != step['supported']:
                raise ValueError('Unsupported vendor step cannot have an executable mapping')
    return artifacts


def imported_playbook(key):
    return load_imported_playbooks().get(key)


def verify_canonical_artifact(key, source_bytes):
    """Validate a fetched source before accepting its normalized import."""
    artifact=imported_playbook(key)
    if artifact is None or not isinstance(source_bytes,bytes):
        return False
    if hashlib.sha256(source_bytes).hexdigest()!=artifact['source_sha256']:
        return False
    text=source_bytes.decode('utf-8')
    names=set(re.findall(r'^\s{6}name: (.+)$',text,re.MULTILINE))
    return all(step['source_step'] in names for step in artifact['steps'])


def check_keys(key):
    artifact=imported_playbook(key)
    return frozenset(artifact['check_keys']) if artifact else frozenset()
