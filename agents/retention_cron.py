#!/usr/bin/env python3
"""
FDA Cyber Control — Retention Cron (Native)

Periodically prunes old events based on retention policy.
"""
from __future__ import annotations

import logging
import os
import signal
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app_shared.sqlite_store import prune_events
from app_shared.retention import read_retention_hours

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [retention-cron] %(message)s",
    handlers=[logging.StreamHandler(), logging.FileHandler(ROOT / "state" / "logs" / "retention-cron.log", mode="a")],
)
logger = logging.getLogger("fda.retention-cron")

running = True


def handle_signal(sig, frame):
    global running
    running = False


signal.signal(signal.SIGTERM, handle_signal)
signal.signal(signal.SIGINT, handle_signal)


def main():
    logger.info("Retention cron started")
    
    while running:
        try:
            hours = read_retention_hours()
            result = prune_events(hours)
            if result.get("events_removed", 0) > 0:
                logger.info("Pruned %d events", result["events_removed"])
        except Exception as exc:
            logger.error("Prune error: %s", exc)
        
        # Sleep for 1 hour
        for _ in range(3600):
            if not running:
                break
            time.sleep(1)
    
    logger.info("Retention cron stopped")


if __name__ == "__main__":
    main()
