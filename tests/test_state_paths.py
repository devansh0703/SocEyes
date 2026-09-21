"""Tests for the shared runtime-state helpers."""

from __future__ import annotations

import json
import os
import tempfile
import threading
import unittest
from pathlib import Path

os.environ["SOC_STATE_DIR"] = tempfile.mkdtemp(prefix="fda-state-paths-")

from app_shared import state_paths  # noqa: E402


class StatePathTests(unittest.TestCase):
    def setUp(self) -> None:
        self.root = Path(tempfile.mkdtemp(prefix="fda-state-root-"))
        self._previous = os.environ["SOC_STATE_DIR"]
        os.environ["SOC_STATE_DIR"] = str(self.root)

    def tearDown(self) -> None:
        os.environ["SOC_STATE_DIR"] = self._previous

    def test_state_path_lives_under_the_configured_root(self) -> None:
        self.assertEqual(state_paths.state_path("response", "policy.json"), self.root / "response" / "policy.json")

    def test_state_root_defaults_to_in_repo_directory(self) -> None:
        del os.environ["SOC_STATE_DIR"]
        try:
            self.assertEqual(state_paths.state_root(), Path("state"))
        finally:
            os.environ["SOC_STATE_DIR"] = str(self.root)

    def test_write_json_round_trips_and_leaves_no_temp_files(self) -> None:
        target = state_paths.state_path("demo", "current.json")
        state_paths.write_json(target, {"run_id": "run-1", "active": True})

        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), {"active": True, "run_id": "run-1"})
        self.assertEqual(state_paths.read_json(target), {"active": True, "run_id": "run-1"})
        leftovers = [path.name for path in target.parent.iterdir() if path.name != "current.json"]
        self.assertEqual(leftovers, [])

    def test_write_json_overwrites_previous_content(self) -> None:
        target = state_paths.state_path("demo", "current.json")
        state_paths.write_json(target, {"run_id": "run-1"})
        state_paths.write_json(target, {"run_id": "run-2"})
        self.assertEqual(state_paths.read_json(target), {"run_id": "run-2"})

    def test_read_json_returns_default_for_missing_or_corrupt_files(self) -> None:
        missing = state_paths.state_path("demo", "nope.json")
        self.assertIsNone(state_paths.read_json(missing))
        self.assertEqual(state_paths.read_json(missing, default={}), {})

        corrupt = state_paths.state_path("demo", "corrupt.json")
        corrupt.parent.mkdir(parents=True, exist_ok=True)
        corrupt.write_text("{not json", encoding="utf-8")
        self.assertIsNone(state_paths.read_json(corrupt))

    def test_append_jsonl_skips_corrupt_lines(self) -> None:
        target = state_paths.state_path("honeypot", "sessions.jsonl")
        state_paths.append_jsonl(target, {"session_id": "one"})
        with target.open("a", encoding="utf-8") as handle:
            handle.write("this is not json\n")
        state_paths.append_jsonl(target, {"session_id": "two"})

        self.assertEqual([row["session_id"] for row in state_paths.read_jsonl(target)], ["one", "two"])

    def test_read_jsonl_limit_keeps_the_tail(self) -> None:
        target = state_paths.state_path("demo", "history.jsonl")
        for index in range(5):
            state_paths.append_jsonl(target, {"index": index})

        self.assertEqual([row["index"] for row in state_paths.read_jsonl(target, limit=2)], [3, 4])

    def test_concurrent_appends_stay_on_their_own_lines(self) -> None:
        target = state_paths.state_path("demo", "concurrent.jsonl")

        def writer(worker: int) -> None:
            for index in range(25):
                state_paths.append_jsonl(target, {"worker": worker, "index": index})

        threads = [threading.Thread(target=writer, args=(worker,)) for worker in range(4)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

        rows = state_paths.read_jsonl(target)
        self.assertEqual(len(rows), 100)
        self.assertEqual({row["worker"] for row in rows}, {0, 1, 2, 3})

    def test_readable_candidates_includes_legacy_locations(self) -> None:
        candidates = state_paths.readable_candidates(state_paths.state_path("demo_runs", "current.json"))

        self.assertEqual(candidates[0], self.root / "demo_runs" / "current.json")
        self.assertIn(Path("state/demo_runs/current.json"), candidates)
        self.assertIn(Path("/tmp/fda-runtime/state/demo_runs/current.json"), candidates)

    def test_writable_path_creates_parent_directories(self) -> None:
        target = state_paths.state_path("deeply", "nested", "file.jsonl")
        resolved = state_paths.writable_path(target)

        self.assertEqual(resolved, target)
        self.assertTrue(resolved.parent.is_dir())


if __name__ == "__main__":
    unittest.main()