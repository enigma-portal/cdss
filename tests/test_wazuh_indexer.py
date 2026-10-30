"""Tests for the Wazuh Indexer API client without a live Wazuh server."""

import json
import ssl
from urllib.error import URLError
from unittest.mock import MagicMock, patch
import unittest

from app.services.wazuh_indexer import WazuhIndexerClient, WazuhIndexerError


class WazuhIndexerClientTests(unittest.TestCase):
    def test_archive_field_discovery_uses_configured_index(self):
        client = WazuhIndexerClient('https://indexer.example', 'reader', 'secret',
                                    index_name='wazuh-archives-*')
        with patch.object(client, '_request_json', return_value={'fields': {}}) as request:
            self.assertEqual(client.field_capabilities(['timestamp', '@timestamp', 'agent.id']),
                             {'fields': {}})
        self.assertEqual(request.call_args.args[0], 'GET')
        self.assertIn('/wazuh-archives-*/_field_caps?', request.call_args.args[1])
        self.assertIn('include_unmapped=true', request.call_args.args[1])
        with self.assertRaises(ValueError):
            client.field_capabilities(['agent.id&size=10000'])

    def test_archive_search_requires_bounded_source_filtered_request(self):
        client = WazuhIndexerClient('https://indexer.example', 'reader', 'secret',
                                    index_name='wazuh-archives-*')
        payload = {'size': 200, '_source': ['timestamp', 'agent.id'],
                   'query': {'bool': {'filter': []}}}
        with patch.object(client, '_request_json', return_value={'hits': {'hits': []}}) as request:
            client.search_documents(payload)
        self.assertEqual(request.call_args.args,
                         ('POST', '/wazuh-archives-*/_search', payload))
        with self.assertRaises(ValueError):
            client.search_documents({'size': 1001, '_source': ['timestamp']})
        with self.assertRaises(ValueError):
            client.search_documents({'size': 200, '_source': []})

    def test_missing_or_malformed_page_sort_is_rejected(self):
        client = WazuhIndexerClient('https://indexer.example', 'reader', 'secret')
        for sort in (None, [], 1, ['time'], [None,'doc'], ['time',None], ['', 'doc']):
            with self.subTest(sort=sort), patch.object(client,'_request_json',return_value={
                    'hits':{'hits':[{'_source':{},'sort':sort}]}}):
                with self.assertRaisesRegex(WazuhIndexerError,'invalid ingestion cursor'):
                    client.fetch_alert_page()

    def test_fetch_alerts_returns_wazuh_sources(self):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "hits": {"hits": [{"_id": "indexer-id", "_source": {"timestamp": "2026-08-12T12:00:00Z"}}]}
        }).encode("utf-8")
        context_manager = MagicMock()
        context_manager.__enter__.return_value = response
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")

        with patch("app.services.wazuh_indexer._open_no_redirect", return_value=context_manager) as open_request:
            alerts = client.fetch_alerts(size=1, since="2026-08-12T00:00:00Z")

        self.assertEqual(alerts[0]["id"], "indexer-id")
        request_body = json.loads(open_request.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(request_body["query"]["bool"]["filter"][0]["range"]["timestamp"]["gte"], "2026-08-12T00:00:00Z")
        self.assertEqual(request_body["sort"][0]["timestamp"]["order"], "desc")

    def test_tls_certificate_error_is_explained(self):
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")
        certificate_error = ssl.SSLCertVerificationError(1, "self signed")
        with patch("app.services.wazuh_indexer._open_no_redirect", side_effect=URLError(certificate_error)):
            with self.assertRaisesRegex(WazuhIndexerError, "TLS certificate verification failed"):
                client.check_connection()

    def test_malformed_json_structure_is_distinguished(self):
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")
        with patch.object(client, "_request_json", return_value={"unexpected": []}):
            with self.assertRaisesRegex(WazuhIndexerError, "malformed JSON"):
                client.fetch_alert_page(size=10)

    def test_incremental_page_uses_search_after_and_returns_cursor(self):
        response = MagicMock()
        response.read.return_value = json.dumps({"hits": {"hits": [{
            "_index": "wazuh-alerts-fixture", "_id": "doc-2", "_source": {"timestamp": "2026-08-24T10:00:01Z"},
            "sort": ["2026-08-24T10:00:01Z", "doc-2"],
        }]}}).encode("utf-8")
        context_manager = MagicMock()
        context_manager.__enter__.return_value = response
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")
        with patch("app.services.wazuh_indexer._open_no_redirect", return_value=context_manager) as opened:
            events, cursor = client.fetch_alert_page(
                size=10, search_after=("2026-08-24T10:00:00Z", "doc-1"))
        body = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(body["search_after"], ["2026-08-24T10:00:00Z", "doc-1"])
        self.assertEqual(body["sort"][0]["timestamp"]["order"], "asc")
        self.assertEqual(events[0]["id"], "doc-2")
        self.assertEqual(cursor, ("2026-08-24T10:00:01Z", "doc-2"))

    def test_numeric_sort_value_keeps_its_opensearch_type(self):
        response = MagicMock()
        response.read.return_value = json.dumps({"hits": {"hits": [{
            "_index": "wazuh-alerts-fixture", "_id": "doc-2", "_source": {"timestamp": "2026-08-24T10:00:01Z"},
            "sort": [1787565601000, "doc-2"],
        }]}}).encode("utf-8")
        context_manager = MagicMock()
        context_manager.__enter__.return_value = response
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")
        with patch("app.services.wazuh_indexer._open_no_redirect", return_value=context_manager) as opened:
            _, cursor = client.fetch_alert_page(size=10,
                search_after=(1787565600000, "doc-1"))
        body = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(body["search_after"], [1787565600000, "doc-1"])
        self.assertIs(type(body["search_after"][0]), int)
        self.assertEqual(cursor, (1787565601000, "doc-2"))

    def test_first_page_bootstraps_from_latest_batch(self):
        response = MagicMock()
        response.read.return_value = json.dumps({"hits": {"hits": [
            {"_index": "wazuh-alerts-fixture", "_id": "new", "_source": {"timestamp": "2026-08-24T10:00:02Z"},
             "sort": ["2026-08-24T10:00:02Z", "new"]},
            {"_index": "wazuh-alerts-fixture", "_id": "old", "_source": {"timestamp": "2026-08-24T10:00:01Z"},
             "sort": ["2026-08-24T10:00:01Z", "old"]},
        ]}}).encode("utf-8")
        context_manager = MagicMock()
        context_manager.__enter__.return_value = response
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")
        with patch("app.services.wazuh_indexer._open_no_redirect", return_value=context_manager) as opened:
            events, cursor = client.fetch_alert_page(size=2)
        body = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(body["sort"][0]["timestamp"]["order"], "desc")
        self.assertEqual([event["id"] for event in events], ["old", "new"])
        self.assertEqual(cursor, ("2026-08-24T10:00:02Z", "new"))

    def test_same_timestamp_documents_are_ordered_and_resumed_by_id(self):
        response = MagicMock()
        response.read.return_value = json.dumps({"hits": {"hits": [
            {"_index": "wazuh-alerts-fixture", "_id": "doc-b", "_source": {"timestamp": "2026-08-24T10:00:00Z"},
             "sort": ["2026-08-24T10:00:00Z", "doc-b"]},
        ]}}).encode("utf-8")
        context_manager = MagicMock(); context_manager.__enter__.return_value = response
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")
        with patch("app.services.wazuh_indexer._open_no_redirect", return_value=context_manager) as opened:
            events, cursor = client.fetch_alert_page(
                size=10, search_after=("2026-08-24T10:00:00Z", "doc-a"))
        body = json.loads(opened.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(body["search_after"], ["2026-08-24T10:00:00Z", "doc-a"])
        self.assertEqual(events[0]["id"], "doc-b")
        self.assertEqual(cursor, ("2026-08-24T10:00:00Z", "doc-b"))


if __name__ == "__main__":
    unittest.main()
