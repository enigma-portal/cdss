"""Shared analyst-facing SIEM collection status semantics."""

from datetime import datetime, timezone
import unittest

from app.services.siem_collection_status import (
    connector_collection_status,
    overall_collection_status,
)


class SiemCollectionStatusTests(unittest.TestCase):
    NOW = datetime(2026, 10, 9, 12, 0, tzinfo=timezone.utc)

    def row(self, *, enabled=1, status='connected', success='2026-10-09 11:59:30'):
        return {'is_enabled': enabled, 'status': status, 'last_success_at': success,
                'poll_status':status, 'last_poll_success_at':success}

    def test_disabled_is_grey_even_with_old_connected_state(self):
        self.assertEqual(connector_collection_status(self.row(enabled=0), now=self.NOW).state, 'disabled')
        self.assertEqual(connector_collection_status(
            self.row(), now=self.NOW, polling_enabled=False).state, 'disabled')

    def test_enabled_failure_cannot_be_active(self):
        state = connector_collection_status(self.row(status='error'), now=self.NOW)
        self.assertEqual(state.state, 'failed')
        self.assertIn('interrupted', state.label)

    def test_recent_successful_poll_is_active(self):
        self.assertEqual(connector_collection_status(self.row(), now=self.NOW).state, 'active')

    def test_unknown_and_stale_are_not_active(self):
        self.assertEqual(connector_collection_status(
            self.row(status='not_tested', success=None), now=self.NOW).state, 'unknown')
        self.assertEqual(connector_collection_status(
            self.row(success=None), now=self.NOW).state, 'unknown')
        self.assertEqual(connector_collection_status(
            self.row(success='2026-10-09 11:50:00'), now=self.NOW).state, 'stale')

    def test_global_banner_uses_worst_enabled_connector_state(self):
        aggregate = overall_collection_status(
            [self.row(), self.row(status='error')], now=self.NOW)
        self.assertEqual(aggregate.state, 'failed')
        self.assertEqual(aggregate.enabled_count, 2)
        self.assertIsNone(aggregate.last_success_at)
        self.assertEqual(overall_collection_status(
            [self.row(enabled=0)], now=self.NOW).state, 'disabled')


if __name__ == '__main__':
    unittest.main()
