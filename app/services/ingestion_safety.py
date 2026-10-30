"""Keep rejected source documents durable before allowing cursor progress."""
import hashlib
import json
import ipaddress
from app.database import get_db_connection
from app.services.siem_endpoint import validated_siem_endpoint, parse_origin

REJECTION_CODES = frozenset(('malformed_event', 'changed_document', 'source_identity_conflict', 'incomplete_identity'))
CONNECTOR_FETCH_FIELDS = ('connector_type','base_url','port','index_pattern','username',
                          'encrypted_password','verify_tls','is_enabled')


class ConnectorChangedError(RuntimeError):
    """Fetched data cannot establish proof for a different configuration."""


def connector_matches_snapshot(connection, snapshot):
    row = connection.execute('SELECT * FROM siem_connections WHERE id=?', (snapshot['id'],)).fetchone()
    return row is not None and all(row[key] == snapshot[key] for key in CONNECTOR_FETCH_FIELDS)


def require_connector_snapshot(connection, snapshot):
    if snapshot is not None and not connector_matches_snapshot(connection, snapshot):
        raise ConnectorChangedError('Connector changed during collection; cursor retained.')


class SourceEventError(ValueError):
    def __init__(self, reason_code):
        if reason_code not in REJECTION_CODES:
            raise ValueError('Unknown source rejection code.')
        self.reason_code = reason_code
        super().__init__('Source event requires operator review.')


def source_namespace(row):
    """Endpoint v1: connector type + canonical HTTPS host/port, never credentials.

    DNS aliases are distinct; DNS resolution, name, account, TLS settings and
    query pattern cannot change identity. Concrete index remains document scope.
    """
    origin, port = validated_siem_endpoint(row['base_url'], row['port'])
    host = parse_origin(origin).hostname
    try:
        host = ipaddress.ip_address(host).compressed
    except ValueError:
        host = host.rstrip('.').encode('idna').decode('ascii').lower()
    return json.dumps(['endpoint-v1', row['connector_type'], host, port], separators=(',', ':'))


def document_identity(event, connection_id):
    index = getattr(event, 'source_index', None)
    document = getattr(event, 'source_document_id', None)
    if connection_id is None or not isinstance(index, str) or not index or not isinstance(document, str) or not document:
        return None
    return connection_id, index, document


def preserve_rejection(event, connection_id, reason_code='malformed_event', *, expected_connector=None):
    if reason_code not in REJECTION_CODES:
        raise ValueError('Unknown source rejection code.')
    identity = document_identity(event, connection_id)
    if identity is None:
        return False  # No stable provenance: fail closed and retain the cursor.
    raw = json.dumps(getattr(event, 'raw_source', event), ensure_ascii=False,
                     allow_nan=False, sort_keys=True, separators=(',', ':'))
    connection = get_db_connection()
    try:
        with connection:
            connection.execute('BEGIN IMMEDIATE')
            require_connector_snapshot(connection, expected_connector)
            row = connection.execute('SELECT * FROM siem_connections WHERE id=?', (connection_id,)).fetchone()
            namespace = source_namespace(row) if row else None
            payload_hash = hashlib.sha256(raw.encode()).hexdigest()
            prior = connection.execute('''SELECT source_namespace FROM rejected_source_events
                WHERE connection_id=? AND source_index=? AND source_document_id=? AND payload_hash=?''',
                (*identity,payload_hash)).fetchone()
            if prior and (namespace is None or prior['source_namespace'] != namespace):
                raise SourceEventError('source_identity_conflict')
            connection.execute('''INSERT OR IGNORE INTO rejected_source_events
                (connection_id,source_index,source_document_id,raw_event_json,payload_hash,reason,source_namespace)
                VALUES(?,?,?,?,?,?,?)''',
                (*identity,raw,payload_hash,reason_code,namespace))
    finally:
        connection.close()
    return True
