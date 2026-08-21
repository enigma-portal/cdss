"""Vendor-neutral SIEM connector contracts and registry."""

from abc import ABC, abstractmethod

from app.services.wazuh_indexer import WazuhIndexerClient


class SiemConnector(ABC):
    """Read-only contract implemented by every supported SIEM adapter."""

    @abstractmethod
    def test_connection(self):
        """Return source health without writing to the SIEM."""

    @abstractmethod
    def fetch_events(self, *, size, since=None, sort_order="desc"):
        """Return vendor events for normalization and ingestion."""


class WazuhIndexerConnector(SiemConnector):
    def __init__(self, **configuration):
        self.client = WazuhIndexerClient(**configuration)

    def test_connection(self):
        return self.client.check_connection()

    def fetch_events(self, *, size, since=None, sort_order="desc"):
        return self.client.fetch_alerts(size=size, since=since, sort_order=sort_order)


CONNECTOR_TYPES = {
    "wazuh_indexer": ("Wazuh Indexer / OpenSearch", WazuhIndexerConnector),
}


def create_connector(connector_type, **configuration):
    try:
        connector_class = CONNECTOR_TYPES[connector_type][1]
    except KeyError as error:
        raise ValueError("Unsupported SIEM connector type.") from error
    return connector_class(**configuration)
