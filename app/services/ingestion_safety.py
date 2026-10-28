"""Keep rejected source documents durable before allowing cursor progress."""
import hashlib
import json
from app.database import get_db_connection


def document_identity(event, connection_id):
    index = getattr(event, 'source_index', None)
    document = getattr(event, 'source_document_id', None)
    if connection_id is None or not isinstance(index, str) or not index or not isinstance(document, str) or not document:
        return None
    return connection_id, index, document


def preserve_rejection(event, connection_id):
    identity = document_identity(event, connection_id)
    if identity is None:
        return False  # No stable provenance: fail closed and retain the cursor.
    raw = json.dumps(getattr(event, 'raw_source', event), ensure_ascii=False,
                     allow_nan=False, sort_keys=True, separators=(',', ':'))
    connection = get_db_connection()
    try:
        with connection:
            connection.execute('''INSERT OR IGNORE INTO rejected_source_events
                (connection_id,source_index,source_document_id,raw_event_json,payload_hash,reason)
                VALUES(?,?,?,?,?,'Source validation or identity conflict; operator review required.')''',
                (*identity,raw,hashlib.sha256(raw.encode()).hexdigest()))
    finally:
        connection.close()
    return True
