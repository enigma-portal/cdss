"""Shared SQLite login budgets; never lock an account across source addresses."""
import hashlib


def _buckets(address, username):
    source = hashlib.sha256((address or 'unknown').encode()).hexdigest()
    pair = hashlib.sha256((source + ':' + username.casefold()).encode()).hexdigest()
    return ('source:' + source, 'pair:' + pair)


def reserve_attempt(connection, address, username, now):
    """Atomically reserve hashing work across workers, cookies and restarts."""
    buckets = _buckets(address, username)
    with connection:
        connection.execute('BEGIN IMMEDIATE')
        connection.execute('DELETE FROM login_attempt_budgets WHERE window_start<=?', (now-60,))
        for bucket, limit in zip(buckets, (30, 5)):
            row = connection.execute('SELECT attempts FROM login_attempt_budgets WHERE bucket=?',
                                     (bucket,)).fetchone()
            if row and row[0] >= limit:
                return False
        for bucket in buckets:
            connection.execute('''INSERT INTO login_attempt_budgets VALUES(?,1,?)
                ON CONFLICT(bucket) DO UPDATE SET attempts=attempts+1''', (bucket, now))
    return True


def clear_account_budget(connection, address, username):
    # Keep the source-wide budget to bound username rotation/credential stuffing.
    with connection:
        connection.execute('DELETE FROM login_attempt_budgets WHERE bucket=?',
                           (_buckets(address, username)[1],))
