"""Additive storage for short-lived, server-enforced login attempt budgets."""


def migrate_auth_security(connection):
    connection.execute('''CREATE TABLE IF NOT EXISTS login_attempt_budgets (
        bucket TEXT PRIMARY KEY, attempts INTEGER NOT NULL,
        window_start INTEGER NOT NULL)''')
    connection.execute('''CREATE INDEX IF NOT EXISTS idx_login_budget_window
        ON login_attempt_budgets(window_start)''')
