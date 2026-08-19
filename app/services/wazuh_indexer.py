"""Read Wazuh alerts securely from the Wazuh Indexer REST API."""

import base64
import json
import os
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import Request, urlopen


class WazuhIndexerError(RuntimeError):
    """Raised when the Wazuh Indexer API cannot be used safely."""


class WazuhIndexerClient:
    """Minimal read-only client for the Wazuh ``wazuh-alerts-*`` indexes."""

    def __init__(
        self, base_url, username, password, index_name="wazuh-alerts-*",
        verify_tls=True, timeout_seconds=10,
    ):
        if not base_url.startswith(("https://", "http://")):
            raise ValueError("WAZUH_INDEXER_URL must begin with https:// or http://.")
        if not username or not password:
            raise ValueError("Wazuh Indexer username and password are required.")
        self.base_url = base_url.rstrip("/")
        self.index_name = index_name
        self.timeout_seconds = timeout_seconds
        encoded_credentials = base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        self.headers = {
            "Accept": "application/json",
            "Authorization": f"Basic {encoded_credentials}",
        }
        self.ssl_context = ssl.create_default_context()
        if not verify_tls:
            self.ssl_context.check_hostname = False
            self.ssl_context.verify_mode = ssl.CERT_NONE

    @classmethod
    def from_environment(cls):
        """Create a client from environment variables, without storing secrets in code."""
        verify_tls = os.getenv("WAZUH_INDEXER_VERIFY_TLS", "true").lower() == "true"
        return cls(
            base_url=os.getenv("WAZUH_INDEXER_URL", "https://localhost:9200"),
            username=os.getenv("WAZUH_INDEXER_USERNAME"),
            password=os.getenv("WAZUH_INDEXER_PASSWORD"),
            index_name=os.getenv("WAZUH_INDEXER_INDEX", "wazuh-alerts-*"),
            verify_tls=verify_tls,
        )

    def _request_json(self, method, path, payload=None):
        data = None if payload is None else json.dumps(payload).encode("utf-8")
        headers = self.headers | ({"Content-Type": "application/json"} if data else {})
        request = Request(
            f"{self.base_url}{path}", data=data, headers=headers, method=method,
        )
        try:
            with urlopen(request, timeout=self.timeout_seconds, context=self.ssl_context) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            raise WazuhIndexerError(
                f"Wazuh Indexer returned HTTP {error.code}. Check the CDSS read-only account."
            ) from error
        except (URLError, TimeoutError, json.JSONDecodeError) as error:
            raise WazuhIndexerError(
                "Could not connect to the Wazuh Indexer API. Check the URL, TLS setting, and network access."
            ) from error

    def fetch_alerts(self, size=100, since=None, sort_order="desc"):
        """Return newest matching raw Wazuh alert documents.

        ``since`` accepts an ISO-8601 time string understood by OpenSearch, for
        example ``2026-08-12T10:00:00Z``.
        """
        if not 1 <= size <= 10_000:
            raise ValueError("size must be between 1 and 10,000.")
        if sort_order not in {"asc", "desc"}:
            raise ValueError("sort_order must be 'asc' or 'desc'.")
        filters = []
        if since:
            filters.append({"range": {"timestamp": {"gte": since}}})
        query = {"bool": {"filter": filters}} if filters else {"match_all": {}}
        payload = {
            "size": size,
            "sort": [{"timestamp": {"order": sort_order}}, {"_id": {"order": sort_order}}],
            "query": query,
        }
        safe_index = quote(self.index_name, safe="*,-")
        response = self._request_json("POST", f"/{safe_index}/_search", payload)
        alerts = []
        for hit in response.get("hits", {}).get("hits", []):
            alert = dict(hit.get("_source", {}))
            alert.setdefault("id", hit.get("_id"))
            alerts.append(alert)
        return alerts

    def check_connection(self):
        """Return the Indexer health result without changing any server data."""
        return self._request_json("GET", "/_cluster/health")
