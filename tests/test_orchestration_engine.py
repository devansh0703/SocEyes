"""Unit tests for the orchestration engine dispatch table refactor."""

import os
import unittest

# Ensure the repo root is importable before the module's own sys.path.insert runs.
os.environ.setdefault("SOC_STATE_DIR", "/tmp/soceyes-tests-state")

from scripts.run_orchestration_engine import (
    _HAND_DISPATCH,
    execute_hand,
    HandContext,
)


# The complete set of hands defined in zeroclaw/hands/*.toml.
EXPECTED_HANDS = [
    "orchestrator_main",
    "elastic_sensor",
    "wazuh_sensor",
    "suricata_sensor",
    "rule_mapper",
    "query_analyst",
    "mitre_mapper",
    "playbook_resolver",
    "response_planner",
    "bandwidth_governor",
    "validation_agent",
    "alert_correlator",
    "evidence_curator",
    "telemetry_curator",
    "run_supervisor",
    "policy_guardian",
    "threat_summarizer",
    "zeroclaw_runtime",
]


class DispatchTableTests(unittest.TestCase):
    """Every hand in zeroclaw/hands must have a registered handler."""

    def test_all_expected_hands_are_registered(self):
        for name in EXPECTED_HANDS:
            self.assertIn(name, _HAND_DISPATCH, f"Hand '{name}' has no handler in _HAND_DISPATCH")

    def test_no_extra_handlers_beyond_known_hands(self):
        """The dispatch table should not contain handlers for undefined hands."""
        unknown = set(_HAND_DISPATCH) - set(EXPECTED_HANDS)
        self.assertEqual(unknown, set(), f"Unexpected handlers in dispatch table: {unknown}")

    def test_dispatch_table_count_matches_expected(self):
        self.assertEqual(len(_HAND_DISPATCH), len(EXPECTED_HANDS))


class ExecuteHandTests(unittest.TestCase):
    """Tests for execute_hand itself — no live Elasticsearch required."""

    def test_unknown_hand_returns_idle_status(self):
        """A hand name with no registered handler should get an 'Idle' step."""
        hand = {"name": "definitely_not_a_real_hand", "active": True}
        result = execute_hand(hand, {})
        self.assertEqual(result["hand_name"], "definitely_not_a_real_hand")
        self.assertEqual(result["status"]["status"], "completed")
        self.assertEqual(len(result["steps"]), 1)
        self.assertEqual(result["steps"][0]["title"], "Idle")
        self.assertTrue(result["findings"])

    def test_result_has_required_fields(self):
        """Every run result must carry the standard metadata fields."""
        hand = {"name": "unknown_hand_for_testing", "active": True}
        result = execute_hand(hand, {})
        for field in ("hand_name", "run_id", "started_at", "finished_at",
                       "status", "steps", "metrics", "findings",
                       "knowledge_added", "duration_ms"):
            self.assertIn(field, result, f"Missing field: {field}")

    def test_failed_handler_produces_failed_status(self):
        """A handler that raises should be caught and reported, not crash."""
        # Register a temporary handler that always raises.
        original = _HAND_DISPATCH.get("test_fail_hand")
        _HAND_DISPATCH["test_fail_hand"] = lambda ctx: (_ for _ in ()).throw(RuntimeError("boom"))
        try:
            hand = {"name": "test_fail_hand", "active": True}
            result = execute_hand(hand, {})
            self.assertEqual(result["status"]["status"], "failed")
            self.assertEqual(result["status"]["error"], "boom")
        finally:
            if original is not None:
                _HAND_DISPATCH["test_fail_hand"] = original
            else:
                del _HAND_DISPATCH["test_fail_hand"]


class HandContextTests(unittest.TestCase):
    """The HandContext dataclass wraps mutable run state for handlers."""

    def test_step_appends_with_timestamp(self):
        ctx = HandContext()
        ctx.step("Test", "detail")
        self.assertEqual(len(ctx.steps), 1)
        self.assertEqual(ctx.steps[0]["title"], "Test")
        self.assertEqual(ctx.steps[0]["detail"], "detail")
        self.assertEqual(ctx.steps[0]["status"], "completed")
        self.assertIn("timestamp", ctx.steps[0])

    def test_step_accepts_custom_status(self):
        ctx = HandContext()
        ctx.step("Warn", "detail", status="warning")
        self.assertEqual(ctx.steps[0]["status"], "warning")

    def test_metrics_findings_knowledge_start_empty(self):
        ctx = HandContext()
        self.assertEqual(ctx.metrics, {})
        self.assertEqual(ctx.findings, [])
        self.assertEqual(ctx.knowledge, [])


if __name__ == "__main__":
    unittest.main()
