"""Dashboard aggregation cache with stale-while-revalidate.

Extracted from main.py. The dashboard aggregates scan millions of SQLite rows
(tens of seconds on a cold cache), so every request is served from cache and
refreshes happen in the background.
"""
from __future__ import annotations

import json
import logging
import os
import threading
import time

logger = logging.getLogger("soceyes.services.dashboard")

# --- dashboard payload cache (key -> (built_at, payload)) -------------------
_DASHBOARD_TTL_SECONDS = float(os.environ.get("SOC_DASHBOARD_TTL_SECONDS", "30"))
_DASHBOARD_REBUILD_WAIT_SECONDS = float(os.environ.get("SOC_DASHBOARD_REBUILD_WAIT_SECONDS", "45"))
_dashboard_cache: dict[str, tuple[float, dict]] = {}
_dashboard_rebuilding: set[str] = set()
_dashboard_lock = threading.Lock()


class DashboardService:
    """Serves dashboard payloads from cache; rebuilds in background."""

    def __init__(self, orchestration_running, rule_count, run_id_provider):
        self._orch_running = orchestration_running
        self._rule_count = rule_count
        self._run_id = run_id_provider

    def build(self, start=None, end=None, run_id=None) -> dict:
        cache_key = f"{start or ''}|{end or ''}|{run_id or self._run_id()}"
        now = time.time()
        with _dashboard_lock:
            cached = _dashboard_cache.get(cache_key)
        if cached and (now - cached[0]) < _DASHBOARD_TTL_SECONDS:
            return cached[1]
        if cache_key in _dashboard_rebuilding:
            # A rebuild is already running: wait briefly for it rather than stacking
            # another multi-second query load on the store.
            deadline = now + _DASHBOARD_REBUILD_WAIT_SECONDS
            while time.time() < deadline:
                time.sleep(0.5)
                with _dashboard_lock:
                    cached = _dashboard_cache.get(cache_key)
                if cached and cached[0] > now:
                    return cached[1]
        if cached:
            # stale-while-revalidate: hand back the stale payload now, refresh async
            with _dashboard_lock:
                _dashboard_rebuilding.add(cache_key)
            threading.Thread(
                target=self._rebuild, args=(start, end, run_id, cache_key),
                daemon=True, name="dashboard-revalidate",
            ).start()
            return cached[1]
        # No cached payload at all (cold start): register the key so concurrent
        # first requests coalesce onto one rebuild instead of stacking queries.
        with _dashboard_lock:
            _dashboard_rebuilding.add(cache_key)
        return self._rebuild(start, end, run_id, cache_key)

    def _rebuild(self, start=None, end=None, run_id=None, cache_key: str = "") -> dict:
        try:
            summary = self._build_payload(start, end, run_id)
            with _dashboard_lock:
                _dashboard_cache[cache_key] = (time.time(), summary)
            return summary
        finally:
            with _dashboard_lock:
                _dashboard_rebuilding.discard(cache_key)

    def _build_payload(self, start=None, end=None, run_id=None) -> dict:
        from agents.orchestration_engine import get_latest_runs
        from app_shared.unified_store import get_analytics_summary, get_kv, get_latest_alerts

        summary = get_analytics_summary(start=start, end=end, run_id=run_id or self._run_id())
        summary["rules_total"] = self._rule_count()
        latest = get_latest_alerts(limit=12)
        summary["latest_alerts"] = [{
            "id": a.get("id", a.get("run_id")),
            "engine": a.get("engine", "correlated"),
            "title": a.get("title", ""),
            "severity": a.get("severity", "medium"),
            "timestamp": a.get("timestamp", ""),
            "message": a.get("message", ""),
            "technique_ids": a.get("technique_ids", []),
            "response_preview": a.get("response_preview", {}),
        } for a in latest]
        if latest:
            rp = latest[0].get("response_preview", {})
            summary["response_preview"] = rp if isinstance(rp, dict) else json.loads(rp) if isinstance(rp, str) else {}
        else:
            summary["response_preview"] = {}

        orch_running = self._orch_running()
        summary["zeroclaw"] = {
            "available": orch_running,
            "summary": "Orchestration engine active" if orch_running else "Orchestration engine not running",
        }
        engine_runs = get_latest_runs()
        hands = []
        for toml in sorted(self._hands_dir().glob("*.toml")):
            name = toml.stem
            run = engine_runs.get(name)
            hands.append({
                "hand_name": name,
                "status": {"status": (run or {}).get("status", {}).get("status", "active" if orch_running else "idle")},
            })
        summary["agents"] = {"hands": hands}
        summary["response_actions_total"] = get_kv("response_actions_total", 0)
        return summary

    @staticmethod
    def _hands_dir():
        from backend.app.paths import _ROOT
        return _ROOT / "zeroclaw" / "hands"


def warmup(service: "DashboardService") -> None:
    """Trigger a cold rebuild in the background at startup."""
    threading.Thread(
        target=service.build, args=(), daemon=True, name="dashboard-warmup",
    ).start()
