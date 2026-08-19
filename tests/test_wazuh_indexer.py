"""Tests for the Wazuh Indexer API client without a live Wazuh server."""

import json
from unittest.mock import MagicMock, patch
import unittest

from app.services.wazuh_indexer import WazuhIndexerClient


class WazuhIndexerClientTests(unittest.TestCase):
    def test_fetch_alerts_returns_wazuh_sources(self):
        response = MagicMock()
        response.read.return_value = json.dumps({
            "hits": {"hits": [{"_id": "indexer-id", "_source": {"timestamp": "2026-08-12T12:00:00Z"}}]}
        }).encode("utf-8")
        context_manager = MagicMock()
        context_manager.__enter__.return_value = response
        client = WazuhIndexerClient("https://indexer.example", "reader", "secret")

        with patch("app.services.wazuh_indexer.urlopen", return_value=context_manager) as open_request:
            alerts = client.fetch_alerts(size=1, since="2026-08-12T00:00:00Z")

        self.assertEqual(alerts[0]["id"], "indexer-id")
        request_body = json.loads(open_request.call_args.args[0].data.decode("utf-8"))
        self.assertEqual(request_body["query"]["bool"]["filter"][0]["range"]["timestamp"]["gte"], "2026-08-12T00:00:00Z")
        self.assertEqual(request_body["sort"][0]["timestamp"]["order"], "desc")


if __name__ == "__main__":
    unittest.main()
