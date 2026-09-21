"""Tests for the response policy helpers (action selection, logging, previews)."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path

os.environ["SOC_STATE_DIR"] = tempfile.mkdtemp(prefix="fda-response-policy-")

from app_shared import response_policy  # noqa: E402
from app_shared.state_paths import read_jsonl  # noqa: E402


class PolicyTests(unittest.TestCase):
    def setUp(self) -> None:
        response_policy.POLICY_STATE_FILE.unlink(missing_ok=True)

    def test_defaults_are_safe(self) -> None:
        policy = response_policy.load_policy()

        self.assertFalse(policy["auto_execute"])
        self.assertEqual(policy["engines"], {"elastic": False, "wazuh": False})

    def test_save_then_load_round_trips_and_normalizes(self) -> None:
        saved = response_policy.save_policy(
            {"auto_execute": 1, "engines": {"elastic": "yes"}, "allow_manual_execute": False}
        )
        loaded = response_policy.load_policy()

        self.assertEqual(saved["engines"], {"elastic": True, "wazuh": False})
        self.assertEqual(loaded, saved)

    def test_corrupt_policy_file_falls_back_to_defaults(self) -> None:
        response_policy.POLICY_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        response_policy.POLICY_STATE_FILE.write_text("{not json", encoding="utf-8")

        self.assertEqual(response_policy.load_policy(), response_policy.DEFAULT_POLICY)

    def test_auto_execution_requires_both_switch_and_engine(self) -> None:
        response_policy.save_policy({"auto_execute": True, "engines": {"elastic": True, "wazuh": False}})

        self.assertTrue(response_policy.is_auto_execution_enabled("elastic"))
        self.assertFalse(response_policy.is_auto_execution_enabled("wazuh"))


class ActionSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        if not response_policy.ACTION_MAP_FILE.exists():
            self.skipTest("config/response/actions.yml is not available from the current working directory")

    def test_exact_technique_match_wins(self) -> None:
        self.assertEqual(response_policy.choose_action(["T1046"]), "block_source_ip")

    def test_unknown_technique_falls_back_to_default(self) -> None:
        self.assertEqual(response_policy.choose_action(["T9999"]), "observe_only")

    def test_command_preview_substitutes_payload_values(self) -> None:
        preview = response_policy.render_command_preview(
            "block_source_ip", {"source_ip": "203.0.113.9", "rule_id": "rule-1", "technique_id": "T1046"}
        )

        self.assertIn("203.0.113.9", preview)
        self.assertIn("rule-1", preview)
        self.assertNotIn("{{", preview)

    def test_action_detail_defaults_to_observe_only(self) -> None:
        detail = response_policy.action_detail("not_a_real_action")

        self.assertEqual(detail["action"], "not_a_real_action")
        self.assertEqual(detail["title"], response_policy.ACTION_DETAILS["observe_only"]["title"])


class ActionLogTests(unittest.TestCase):
    def test_run_logged_command_appends_the_payload(self) -> None:
        target = response_policy.run_logged_command("block_source_ip", {"ip": "203.0.113.10"})

        self.assertEqual(Path(target), response_policy.ACTION_LOG_DIR / "blocklist.jsonl")
        self.assertEqual(read_jsonl(Path(target))[-1], {"ip": "203.0.113.10"})

    def test_unknown_action_uses_the_generic_log(self) -> None:
        target = response_policy.run_logged_command("mystery_action", {"value": 1})

        self.assertEqual(Path(target).name, "actions.jsonl")

    def test_every_mapped_action_is_logged_under_its_own_file(self) -> None:
        target = response_policy.run_logged_command("quarantine_endpoint", {"ip": "10.0.0.1"})

        self.assertEqual(Path(target).name, "quarantined_endpoints.jsonl")


if __name__ == "__main__":
    unittest.main()