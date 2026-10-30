"""Every actual SIEM transport path enforces the same HTTPS destination policy."""
import ssl
import os
from urllib.error import URLError
import unittest
from unittest.mock import patch, MagicMock
from urllib.request import Request
from app.services.wazuh_indexer import WazuhIndexerClient, _open_no_redirect, _PinnedHTTPSConnection


class EndpointHardeningTests(unittest.TestCase):
    def test_environment_and_client_paths_reject_cleartext_credentials(self):
        with self.assertRaises(ValueError):
            WazuhIndexerClient('http://siem.example','reader','fixture')

    def test_actual_transport_blocks_forbidden_resolved_destination(self):
        request=Request('https://siem.example:9200/_cluster/health')
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('127.0.0.1',9200))]), \
             patch('app.services.wazuh_indexer.build_opener') as opened:
            try:
                _open_no_redirect(request,ssl.create_default_context(),10)
            except ValueError:
                pass
            self.assertFalse(opened.called,'Forbidden destination reached the transport')

    def test_private_siem_destination_is_allowed_without_redirects(self):
        request=Request('https://siem.example:9200/_cluster/health')
        with patch('socket.getaddrinfo',return_value=[(2,1,6,'',('10.10.10.10',9200))]), \
             patch('app.services.wazuh_indexer.build_opener') as opened:
            response=object()
            opened.return_value.open.return_value=response
            self.assertIs(_open_no_redirect(request,ssl.create_default_context(),10),response)

    def test_dns_change_cannot_redirect_connection_after_validation(self):
        allowed=(2,1,6,'',('10.10.10.10',9200))
        rebound=(2,1,6,'',('127.0.0.1',9200))
        calls=[]
        def connect(sock,address):
            calls.append(address)
            raise TimeoutError('offline stop before sending credentials')
        with patch.dict(os.environ,{},clear=True), \
             patch('socket.getaddrinfo',side_effect=[[allowed],[rebound]]), \
             patch('socket.socket.connect',new=connect):
            try:
                _open_no_redirect(Request('https://siem.example:9200/'),ssl.create_default_context(),1)
            except (TimeoutError,URLError):
                pass
        self.assertEqual(calls,[('10.10.10.10',9200)])

    def test_unavailable_socket_family_falls_back_without_losing_tls_hostname(self):
        endpoints=[(10,1,6,'',('fd00::1',9200,0,0)),(2,1,6,'',('10.10.10.10',9200))]
        context=MagicMock()
        connection=_PinnedHTTPSConnection('siem.example:9200',endpoints,context=context,timeout=1)
        sock=MagicMock()
        with patch('socket.socket',side_effect=[OSError('IPv6 unavailable'),sock]):
            try:
                connection.connect()
            except OSError as error:
                self.fail('Validated IPv4 fallback was not attempted: '+str(error))
        self.assertIs(connection.sock,context.wrap_socket.return_value)
        self.assertEqual(context.wrap_socket.call_args.kwargs['server_hostname'],'siem.example')
        self.assertEqual(sock.connect.call_args.args[0],('10.10.10.10',9200))
