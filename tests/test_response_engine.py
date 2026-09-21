"""Tests for the AI-assisted response engine and nftables enforcement.

Covers the behaviors that make the detect -> AI triage -> respond chain real:
- Alerts are processed exactly once (dedup via persisted processed-set)
- Auto-execution requires the operator policy gate AND a true-positive
  AI verdict with sufficient confidence
- Dry-run never writes runtime control files
- block_egress dispatches, invalid policies are rejected, rollbacks persist
"""
from __future__ import annotations

import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock

os.environ.setdefault("SOC_STATE_DIR", tempfile.mkdtemp(prefix="fda-response-engine-"))

from agents import response_engine  # noqa: E402
from app_shared import response_policy, response_state  # noqa: E402
from app_shared.unified_store import get_kv, init_db, search_alerts, set_kv, store_alert  # noqa: E402
from backend.app.core import enforce  # noqa: E402
from backend.app.core.enforce import (  # noqa: E402
    EnforcementPolicy,
    EnforceAction,
    PendingRollback,
    _execute_rollback,
    _rollback_already_gone,
)


def _make_alert(**overrides) -> dict:
    alert = {
        "id": "alert-test-1",
        "engine": "correlated",
        "severity": "high",
        "title": "Port scan reconnaissance (T1046)",
        "message": "TCP scan from 203.0.113.50",
        "rule_id": "CAPTURE-T1046",
        "source_ip": "203.0.113.50",
        "destination_ip": "198.51.100.10",
        "technique_ids": ["T1046"],
    }
    alert.update(overrides)
    return alert


class EngineTestBase(unittest.TestCase):
    def setUp(self) -> None:
        # Hermetic: never hit the real LLM API from tests, even when
        # NVIDIA_API_KEY is present in the environment. Returning None
        # exercises the rule-based triage fallback path.
        llm_patch = mock.patch("app_shared.nvidia_ai.chat_completion", return_value=None)
        llm_patch.start()
        self.addCleanup(llm_patch.stop)
        response_policy.POLICY_STATE_FILE.unlink(missing_ok=True)
        os.environ.pop("SOC_RESPONSE_DRY_RUN", None)
        response_engine._save_processed(set())
        for path in response_state.FILES.values():
            if path.exists():
                path.unlink()

    def tearDown(self) -> None:
        response_policy.POLICY_STATE_FILE.unlink(missing_ok=True)
        os.environ.pop("SOC_RESPONSE_DRY_RUN", None)


class PolicyGateTests(EngineTestBase):
    def test_policy_disabled_holds_enforcement(self) -> None:
        record = response_engine.process_alert(_make_alert())

        self.assertEqual(record["action"], "observe_only")
        self.assertEqual(record["status"], "observed")
        self.assertFalse(record["auto_execution_allowed"])

    def test_policy_enabled_executes_recommended_action(self) -> None:
        response_policy.save_policy({"auto_execute": True, "engines": {"elastic": False, "wazuh": False}})
        record = response_engine.process_alert(_make_alert())

        # Rule-based triage (no API key in tests): high severity -> true_positive.
        self.assertEqual(record["action"], "block_source_ip")
        self.assertEqual(record["status"], "executed")
        self.assertTrue(record["auto_execution_allowed"])

    def test_llm_true_positive_verdict_drives_enforcement(self) -> None:
        """A real LLM verdict (medium-severity alert) gates the response."""
        response_policy.save_policy({"auto_execute": True, "engines": {}})
        verdict = (
            '{"verdict": "true_positive", "confidence": 0.93, '
            '"mitre_technique": "T1046", "reasoning": "Scan pattern from external host."}'
        )
        with mock.patch("app_shared.nvidia_ai.chat_completion", return_value=verdict):
            record = response_engine.process_alert(_make_alert(severity="medium"))

        self.assertEqual(record["ai_triage"]["verdict"], "true_positive")
        self.assertEqual(record["ai_triage"]["confidence"], 0.93)
        self.assertEqual(record["action"], "block_source_ip")
        self.assertEqual(record["status"], "executed")

    def test_llm_false_positive_verdict_holds_enforcement(self) -> None:
        response_policy.save_policy({"auto_execute": True, "engines": {}})
        verdict = (
            '{"verdict": "false_positive", "confidence": 0.81, '
            '"mitre_technique": null, "reasoning": "Internal monitoring host."}'
        )
        with mock.patch("app_shared.nvidia_ai.chat_completion", return_value=verdict):
            record = response_engine.process_alert(_make_alert(severity="high"))

        self.assertEqual(record["ai_triage"]["verdict"], "false_positive")
        self.assertEqual(record["action"], "observe_only")
        self.assertEqual(record["status"], "observed")

    def test_false_positive_verdict_holds_enforcement_even_when_allowed(self) -> None:
        response_policy.save_policy({"auto_execute": True, "engines": {"elastic": False, "wazuh": False}})
        # Low severity => rule-based triage verdict is false_positive.
        record = response_engine.process_alert(_make_alert(severity="low"))

        self.assertEqual(record["action"], "observe_only")
        self.assertEqual(record["status"], "observed")

    def test_engine_gate_blocks_engines_with_a_disabled_switch(self) -> None:
        response_policy.save_policy({"auto_execute": True, "engines": {"elastic": True, "wazuh": False}})
        record = response_engine.process_alert(_make_alert(engine="wazuh"))

        self.assertEqual(record["action"], "observe_only")
        self.assertEqual(record["status"], "observed")


class AlertDedupTests(EngineTestBase):
    def test_alerts_are_processed_exactly_once(self) -> None:
        init_db()
        store_alert("correlated", "high", "Scan one", rule_id="R1", source_ip="203.0.113.51", technique_ids=["T1046"])
        store_alert("correlated", "critical", "Scan two", rule_id="R2", source_ip="203.0.113.52", technique_ids=["T1046"])

        first = response_engine.process_pending_alerts()
        second = response_engine.process_pending_alerts()

        self.assertEqual(len(first), 2)
        self.assertEqual(second, [])
        self.assertEqual(len(response_engine._load_processed()), 2)

    def test_processed_set_is_capped(self) -> None:
        response_engine._save_processed({f"alert-{i}" for i in range(response_engine.PROCESSED_CAP + 100)})

        processed = response_engine._load_processed()

        self.assertLessEqual(len(processed), response_engine.PROCESSED_CAP)
        self.assertIn(f"alert-{response_engine.PROCESSED_CAP + 99}", processed)


class DryRunSafetyTests(EngineTestBase):
    def test_dry_run_does_not_write_control_files(self) -> None:
        response_policy.save_policy({"auto_execute": True, "engines": {}})
        response_engine.execute_response_action(action="block_source_ip", source_ip="203.0.113.60", rule_id="R9")

        self.assertFalse(response_state.FILES["block_source_ip"].exists())

    def test_live_run_writes_control_file(self) -> None:
        os.environ["SOC_RESPONSE_DRY_RUN"] = "false"
        response_engine.execute_response_action(action="block_source_ip", source_ip="203.0.113.61", rule_id="R10")

        entries = response_state.load_list(response_state.FILES["block_source_ip"])
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["ip"], "203.0.113.61")
        self.assertIn("ttl_seconds", entries[0])

    def test_expired_control_entries_are_pruned(self) -> None:
        os.environ["SOC_RESPONSE_DRY_RUN"] = "false"
        path = response_state.FILES["block_source_ip"]
        now = datetime.now(timezone.utc)
        response_state.save_list(path, [
            {"ip": "203.0.113.70", "ttl_seconds": 1,
             "updated_at": (now - timedelta(hours=1)).isoformat()},
            {"ip": "203.0.113.71", "ttl_seconds": 1800,
             "updated_at": now.isoformat()},
        ])

        removed = response_engine._prune_expired_controls()

        self.assertEqual(removed, 1)
        remaining = response_state.load_list(path)
        self.assertEqual([e["ip"] for e in remaining], ["203.0.113.71"])


class EnforceDispatchTests(unittest.TestCase):
    def test_block_egress_renders_dry_run_command(self) -> None:
        result = EnforceAction(EnforcementPolicy(
            action="block_egress", source_ip="203.0.113.80", dry_run=True,
        ))

        self.assertTrue(result.success)
        self.assertTrue(result.dry_run)
        self.assertIn("soceyes_egress_blocked", result.executed_command)

    def test_block_source_ip_dry_run_uses_timeout_set(self) -> None:
        result = EnforceAction(EnforcementPolicy(
            action="block_source_ip", source_ip="203.0.113.81", ttl_seconds=60, dry_run=True,
        ))

        self.assertIn("soceyes_blocked_ips", result.executed_command)
        self.assertIn("timeout 60s", result.executed_command)

    def test_throttle_dry_run_includes_accept_and_drop(self) -> None:
        result = EnforceAction(EnforcementPolicy(
            action="throttle_service", source_ip="203.0.113.82",
            requests_per_minute=30, dry_run=True,
        ))

        self.assertIn("limit rate 30/minute accept", result.executed_command)
        self.assertIn("drop", result.executed_command)

    def test_invalid_ip_is_rejected_before_anything_runs(self) -> None:
        result = EnforceAction(EnforcementPolicy(
            action="block_source_ip", source_ip="not-an-ip", dry_run=True,
        ))

        self.assertFalse(result.success)
        self.assertIn("Invalid IP", result.error)

    def test_throttle_requires_positive_rate(self) -> None:
        result = EnforceAction(EnforcementPolicy(
            action="throttle_service", source_ip="203.0.113.83",
            requests_per_minute=0, dry_run=True,
        ))

        self.assertFalse(result.success)
        self.assertIn("requests_per_minute", result.error)

    def test_disable_account_rejects_flag_injection(self) -> None:
        result = EnforceAction(EnforcementPolicy(
            action="disable_account", source_ip="-rf", dry_run=True,
        ))

        self.assertFalse(result.success)
        self.assertIn("username", result.error)


class RollbackTests(unittest.TestCase):
    def test_pending_rollback_json_round_trip(self) -> None:
        entry = PendingRollback(
            kind="element", rollback_at=123.5, description="block 1.2.3.4",
            payload={"set_name": "soceyes_blocked_ips", "element": "1.2.3.4"},
            log_file="/tmp/x.log",
        )

        restored = PendingRollback.from_json(entry.to_json())

        self.assertEqual(restored.kind, entry.kind)
        self.assertEqual(restored.rollback_at, entry.rollback_at)
        self.assertEqual(restored.payload, entry.payload)

    def test_command_rollback_runs(self) -> None:
        entry = PendingRollback(kind="command", rollback_at=0.0, description="noop",
                                payload={"argv": ["true"]})

        self.assertTrue(_execute_rollback("test-cmd", entry))

    def test_missing_target_counts_as_rolled_back(self) -> None:
        self.assertTrue(_rollback_already_gone("Error: No such file or directory"))
        self.assertFalse(_rollback_already_gone("permission denied"))


class StoreParityTests(unittest.TestCase):
    """The unified store is the only store: kv + alerts round-trip."""

    def test_state_kv_round_trip(self) -> None:
        set_kv("test_key", "v1")
        self.assertEqual(get_kv("test_key"), "v1")
        set_kv("test_key", "v2")
        self.assertEqual(get_kv("test_key"), "v2")

    def test_search_alerts_returns_stored_alerts(self) -> None:
        init_db()
        alert_id = store_alert("correlated", "high", "Parity alert", rule_id="RP1",
                               source_ip="203.0.113.90", technique_ids=["T1046"])
        alerts = [a for a in search_alerts(limit=50) if a.get("id") == alert_id]

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["technique_ids"], ["T1046"])


if __name__ == "__main__":
    unittest.main()
