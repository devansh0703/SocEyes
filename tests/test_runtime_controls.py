"""Tests for the live response control plane (blocklists, rate limits)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest import mock

os.environ["FDA_STATE_DIR"] = tempfile.mkdtemp(prefix="fda-runtime-controls-")
# Always re-read control files so a test sees the file it just wrote.
os.environ["FDA_CONTROL_CACHE_TTL_SECONDS"] = "0"

from app_shared.state_paths import write_json  # noqa: E402
from backend.app import runtime_controls  # noqa: E402


class FakeClient:
    def __init__(self, host: str) -> None:
        self.host = host


class FakeRequest:
    def __init__(self, headers: dict[str, str] | None = None, host: str = "10.0.0.5") -> None:
        self.headers = headers or {}
        self.client: Any = FakeClient(host) if host else None


def write_controls(path: Path, payload: Any) -> None:
    """Write a control file to the exact location the module under test reads."""
    write_json(path, payload)


class RateLimitTests(unittest.TestCase):
    def setUp(self) -> None:
        runtime_controls.RATE_LIMITS_FILE.unlink(missing_ok=True)
        with runtime_controls._counter_lock:  # noqa: SLF001 - test isolation
            runtime_controls._counters.clear()

    def test_requests_pass_when_no_rule_matches(self) -> None:
        allowed, remaining, rule = runtime_controls.check_and_count_rate_limit("/api/dashboard", "10.0.0.5")

        self.assertTrue(allowed)
        self.assertEqual(remaining, 0)
        self.assertIsNone(rule)

    def test_requests_are_blocked_after_the_configured_threshold(self) -> None:
        write_controls(runtime_controls.RATE_LIMITS_FILE, [{"source_ip": "", "path": "/api/login", "requests_per_minute": 2}])

        first = runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")
        second = runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")
        third = runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")

        self.assertEqual((first[0], first[1]), (True, 1))
        self.assertEqual((second[0], second[1]), (True, 0))
        self.assertFalse(third[0])
        self.assertEqual(third[2]["requests_per_minute"], 2)

    def test_counters_are_scoped_per_source_ip(self) -> None:
        write_controls(runtime_controls.RATE_LIMITS_FILE, [{"source_ip": "", "path": "/api/login", "requests_per_minute": 1}])

        runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")
        blocked = runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")
        other_client = runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.6")

        self.assertFalse(blocked[0])
        self.assertTrue(other_client[0])

    def test_source_ip_scoped_rule_ignores_other_clients(self) -> None:
        write_controls(runtime_controls.RATE_LIMITS_FILE, [{"source_ip": "1.1.1.1", "path": "/api/x", "requests_per_minute": 1}])

        self.assertIsNone(runtime_controls.matching_rate_limit("/api/x", "2.2.2.2"))
        self.assertIsNotNone(runtime_controls.matching_rate_limit("/api/x", "1.1.1.1"))

    def test_longest_matching_path_wins(self) -> None:
        write_controls(
            runtime_controls.RATE_LIMITS_FILE,
            [
                {"source_ip": "", "path": "/api", "requests_per_minute": 100},
                {"source_ip": "", "path": "/api/secure", "requests_per_minute": 5},
            ],
        )

        rule = runtime_controls.matching_rate_limit("/api/secure/data", "10.0.0.5")

        self.assertIsNotNone(rule)
        self.assertEqual(rule["requests_per_minute"], 5)

    def test_counters_are_cleared_when_the_minute_window_rolls_over(self) -> None:
        write_controls(runtime_controls.RATE_LIMITS_FILE, [{"source_ip": "", "path": "/api/login", "requests_per_minute": 10}])
        runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")
        self.assertEqual(len(runtime_controls.counter_snapshot()), 1)

        runtime_controls._counter_bucket = "197001010000"  # noqa: SLF001 - simulate a stale window
        runtime_controls.check_and_count_rate_limit("/api/login", "10.0.0.5")

        snapshot = runtime_controls.counter_snapshot()
        self.assertEqual(len(snapshot), 1)
        self.assertTrue(all(not key.endswith(":197001010000") for key in snapshot))

    def test_counter_map_is_capped(self) -> None:
        write_controls(runtime_controls.RATE_LIMITS_FILE, [{"source_ip": "", "path": "/api/login", "requests_per_minute": 10}])
        with mock.patch.object(runtime_controls, "MAX_COUNTER_KEYS", 2):
            for index in range(5):
                runtime_controls.check_and_count_rate_limit("/api/login", f"10.0.0.{index}")

        self.assertLessEqual(len(runtime_controls.counter_snapshot()), 2)


class ControlListTests(unittest.TestCase):
    def test_blocked_ips_and_disabled_accounts_are_detected(self) -> None:
        write_controls(runtime_controls.BLOCKED_IPS_FILE, [{"ip": "203.0.113.7"}])
        write_controls(runtime_controls.DISABLED_ACCOUNTS_FILE, [{"username": "baduser"}])

        self.assertTrue(runtime_controls.is_blocked_ip("203.0.113.7"))
        self.assertFalse(runtime_controls.is_blocked_ip("203.0.113.8"))
        self.assertTrue(runtime_controls.is_disabled_account("baduser"))
        self.assertFalse(runtime_controls.is_disabled_account("gooduser"))

    def test_load_controls_returns_every_registry(self) -> None:
        controls = runtime_controls.load_controls()

        self.assertEqual(
            sorted(controls),
            ["blocked_ips", "disabled_accounts", "isolated_hosts", "quarantined_endpoints", "rate_limits"],
        )

    def test_missing_control_files_read_as_empty_lists(self) -> None:
        missing = runtime_controls.BLOCKED_IPS_FILE
        missing.unlink(missing_ok=True)

        self.assertEqual(runtime_controls.load_list(missing), [])

    def test_client_ip_prefers_forwarded_header(self) -> None:
        request = FakeRequest(headers={"x-forwarded-for": "198.51.100.9, 10.0.0.1"})

        self.assertEqual(runtime_controls.client_ip_from_request(request), "198.51.100.9")

    def test_client_ip_falls_back_to_peer_address(self) -> None:
        self.assertEqual(runtime_controls.client_ip_from_request(FakeRequest(host="10.1.2.3")), "10.1.2.3")

    def test_enforcement_response_is_json(self) -> None:
        response = runtime_controls.enforcement_response("blocked by policy", 403)

        self.assertEqual(response.status_code, 403)
        self.assertIn(b"blocked by policy", response.body)


if __name__ == "__main__":
    unittest.main()