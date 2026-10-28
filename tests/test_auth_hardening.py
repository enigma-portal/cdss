"""Authentication failures are bounded by the server, independent of cookies."""
import unittest
import time
from unittest.mock import patch

import test_auth as fixtures
from run import app


class AuthHardeningTests(unittest.TestCase):
    setUp = fixtures.AuthenticationTests.setUp
    tearDown = fixtures.AuthenticationTests.tearDown
    _csrf = fixtures.AuthenticationTests._csrf
    _create_admin = fixtures.AuthenticationTests._create_admin

    def bad_login(self, client, address='192.0.2.10'):
        client.get('/login', environ_overrides={'REMOTE_ADDR': address})
        with client.session_transaction() as session:
            token = session['csrf_token']
        return client.post('/login', data={'csrf_token': token,
            'username': 'admin-test', 'password': 'wrong'},
            environ_overrides={'REMOTE_ADDR': address})

    def test_fresh_cookie_does_not_reset_server_login_throttle(self):
        self._create_admin()
        for _ in range(5):
            self.bad_login(app.test_client())
        response = self.bad_login(app.test_client())
        self.assertEqual(response.status_code, 429)

    def test_throttle_cannot_lock_the_account_from_a_different_source(self):
        self._create_admin()
        for _ in range(5):
            self.bad_login(app.test_client())
        other = app.test_client()
        other.get('/login')
        with other.session_transaction() as session:
            token = session['csrf_token']
        result = other.post('/login', data={'csrf_token': token,
            'username': 'admin-test', 'password': 'StrongTesting123'},
            environ_overrides={'REMOTE_ADDR':'192.0.2.11'})
        self.assertEqual(result.status_code, 302)

    def test_automatic_refresh_cannot_extend_idle_session(self):
        start = int(time.time())
        with patch('app.auth.time.time', return_value=start):
            self._create_admin()
        with patch('app.auth.time.time', return_value=start+100):
            self.client.get('/health')
            self.client.get('/static/js/session.js')
            with self.client.session_transaction() as session:
                self.assertEqual(session['last_activity'], start)

    def test_page_refresh_is_removed_and_real_navigation_extends_session(self):
        from app.database import get_db_connection
        start = int(time.time())
        with patch('app.auth.time.time', return_value=start):
            self._create_admin()
        connection = get_db_connection()
        with connection:
            connection.execute('''INSERT INTO siem_connections(name,connector_type,base_url,
                port,index_pattern,username,encrypted_password,verify_tls,is_enabled,status)
                VALUES('offline','wazuh_indexer','https://fixture.invalid',9200,
                    'wazuh-alerts-*','reader',X'01',1,1,'connected')''')
        connection.close()
        with patch('app.auth.time.time', return_value=start+100):
            response = self.client.get('/')
            self.assertNotIn(b'http-equiv="refresh"', response.data)
            with self.client.session_transaction() as session:
                self.assertEqual(session['last_activity'], start+100)
