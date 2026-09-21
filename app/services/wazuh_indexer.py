"""Read Wazuh alerts securely from the Wazuh Indexer REST API."""

import base64
import json
import os
import ssl
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, HTTPSHandler, Request, build_opener


class WazuhIndexerError(RuntimeError):
    """Raised when the Wazuh Indexer API cannot be used safely."""


class _NoRedirect(HTTPRedirectHandler):
    """Prevent a configured SIEM from redirecting CDSS to another target."""

    def redirect_request(self, request, file_pointer, code, message, headers, new_url):
        return None


def _open_no_redirect(request, context, timeout):
    return build_opener(_NoRedirect(), HTTPSHandler(context=context)).open(
        request, timeout=timeout,
    )


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
            with _open_no_redirect(request, self.ssl_context, self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except HTTPError as error:
            if error.code == 401:
                message = "Authentication failed (HTTP 401). Check the read-only username and password."
            elif error.code == 403:
                message = "Authorization failed (HTTP 403). The SIEM account lacks read permissions."
            elif 300 <= error.code < 400:
                message = "SIEM redirects are blocked to prevent unsafe destination changes."
            else:
                message = f"SIEM API returned HTTP {error.code}."
            raise WazuhIndexerError(
                message
            ) from error
        except URLError as error:
            if (isinstance(error.reason, ssl.SSLCertVerificationError)
                    or "CERTIFICATE_VERIFY_FAILED" in str(error.reason)):
                message = ("TLS certificate verification failed. For a lab self-signed certificate, "
                           "turn off TLS verification; for production, install the trusted CA certificate.")
            else:
                message = "Network connection failed. Check SIEM address, port, firewall, and routing."
            raise WazuhIndexerError(
                message
            ) from error
        except TimeoutError as error:
            raise WazuhIndexerError("SIEM connection timed out after 10 seconds.") from error
        except json.JSONDecodeError as error:
            raise WazuhIndexerError("SIEM returned an invalid non-JSON response.") from error

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
        for hit in self._validated_hits(response):
            alert = dict(hit.get("_source", {}))
            alert.setdefault("id", hit.get("_id"))
            alerts.append(alert)
        return alerts

    @staticmethod
    def _validated_hits(response):
        """Reject structurally malformed JSON instead of treating it as no alerts."""
        if not isinstance(response, dict) or not isinstance(response.get("hits"), dict):
            raise WazuhIndexerError("SIEM returned malformed JSON: hits object is unavailable.")
        hits = response["hits"].get("hits")
        if not isinstance(hits, list) or not all(isinstance(hit, dict) for hit in hits):
            raise WazuhIndexerError("SIEM returned malformed JSON: alert hits must be a list.")
        return hits

    def fetch_alert_page(self, size=100, search_after=None):
        """Return a deterministic page and restart-safe cursor.

        A new connector bootstraps from the latest bounded batch. Subsequent
        calls move forward from the saved cursor in ascending order.
        """
        if not 1 <= size <= 10_000:
            raise ValueError("size must be between 1 and 10,000.")
        bootstrap_latest = search_after is None
        order = "desc" if bootstrap_latest else "asc"
        payload = {
            "size": size,
            "sort": [{"timestamp": {"order": order}}, {"_id": {"order": order}}],
            "query": {"match_all": {}},
        }
        if search_after:
            if (not isinstance(search_after, (list, tuple)) or len(search_after) != 2
                    or not all(isinstance(item, str) for item in search_after)):
                raise ValueError("search_after cursor must contain timestamp and document ID.")
            payload["search_after"] = list(search_after)
        safe_index = quote(self.index_name, safe="*,-")
        response = self._request_json("POST", f"/{safe_index}/_search", payload)
        hits = self._validated_hits(response)
        alerts = []
        ordered_hits = list(reversed(hits)) if bootstrap_latest else hits
        for hit in ordered_hits:
            source = hit.get("_source")
            if not isinstance(source, dict):
                continue
            alert = dict(source)
            alert.setdefault("id", hit.get("_id"))
            alerts.append(alert)
        cursor_hit = hits[0] if bootstrap_latest and hits else hits[-1] if hits else None
        next_cursor = tuple(cursor_hit.get("sort", ())) if cursor_hit else None
        if next_cursor and len(next_cursor) != 2:
            raise WazuhIndexerError("SIEM returned an invalid ingestion cursor.")
        return alerts, next_cursor

    def check_connection(self):
        """Return the Indexer health result without changing any server data."""
        return self._request_json("GET", "/_cluster/health")
