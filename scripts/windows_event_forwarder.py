#!/usr/bin/env python3
"""Windows Event Log forwarder agent.

Runs on a Windows host, collects events via wevtutil or WinRM,
and forwards them to the SocEyes API for detection.

This is a real script that uses wevtutil (built into Windows) to
export events and POST them to the SocEyes API.
"""
from __future__ import annotations

import json
import logging
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.INFO, format="%(asctime⟩ [windows-agent] %(message)s")
logger = logging.getLogger("soceyes.windows-agent")

# Configuration
SOC_API_URL = os.environ.get("SOC_API_URL", "http://localhost:8000")
SOC_BATCH_SIZE = int(os.environ.get("SOC_BATCH_SIZE", "50"))
SOC_INTERVAL_SECONDS = int(os.environ.get("SOC_INTERVAL_SECONDS", "60"))

# Windows Event Log channels to monitor
DEFAULT_CHANNELS = [
    "Security",
    "System",
    "Application",
    "Microsoft-Windows-Sysmon/Operational",
    "Microsoft-Windows-Windows Defender/Operational",
    "Microsoft-Windows-TaskScheduler/Operational",
]


def query_events(channel: str, start_time: str | None = None, limit: int = 100) -> list[dict]:
    """Query Windows Event Log via wevtutil."""
    wevtutil = Path(os.environ.get("WINDOWS_SYSTEM_ROOT", r"C:\Windows\System32")) / "wevtutil.exe"
    if not wevtutil.exists():
        logger.warning("wevtutil.exe not found — not running on Windows")
        return []

    cmd = [str(wevtutil), "qe", channel, "/f:json", "/c:str(limit)"]
    if start_time:
        cmd.extend(["/q", f"*[System[TimeCreated[@SystemTime>='{start_time}']]]"])

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.warning("wevtutil query failed for %s: %s", channel, result.stderr[:200])
            return []
        return json.loads(result.stdout)
    except Exception as exc:
        logger.warning("wevtutil query error for %s: %s", channel, exc)
        return []


def forward_to_api(events: list[dict]) -> bool:
    """Forward collected events to the SocEyes API."""
    import requests
    try:
        r = requests.post(
            f"{SOC_API_URL}/api/events/ingest",
            json=events,
            headers={"Content-Type": "application/json"},
            timeout=30,
        )
        return r.status_code == 200
    except Exception as exc:
        logger.warning("API forward failed: %s", exc)
        return False


def main():
    """Main loop: collect and forward events."""
    logger.info("Windows Event Log forwarder started")
    logger.info("API: %s, Channels: %d, Interval: %ds", SOC_API_URL, len(DEFAULT_CHANNELS), SOC_INTERVAL_SECONDS)

    while True:
        all_events = []
        for channel in DEFAULT_CHANNELS:
            events = query_events(channel, limit=SOC_BATCH_SIZE)
            all_events.extend(events)

        if all_events:
            if forward_to_api(all_events):
                logger.info("Forwarded %d events", len(all_events))
            else:
                logger.warning("Failed to forward %d events", len(all_events))
        else:
            logger.info("No new events")

        time.sleep(SOC_INTERVAL_SECONDS)


if __name__ == "__main__":
    main()
