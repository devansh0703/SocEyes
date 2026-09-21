"""SQLite footprint management.

Keeps the WAL file bounded and tunes connection pragmas so a long-running
deployment does not silently grow a multi-gigabyte -wal file (observed at
1.09 GB before this module existed) or hold more memory than needed.

Two mechanisms:
* ``apply_footprint_pragmas(conn)`` — per-connection settings:
  ``wal_autocheckpoint`` bounds how many WAL pages accumulate before SQLite
  checkpoints automatically, and a small page cache + mmap keeps RSS low.
* ``start_wal_maintenance()`` — a daemon thread that periodically forces a
  ``wal_checkpoint(TRUNCATE)`` so the WAL file actually shrinks on disk (the
  auto-checkpoint recycles pages but does not truncate the file).
"""
from __future__ import annotations

import logging
import os
import sqlite3
import threading
import time

logger = logging.getLogger("soceyes.db.maintenance")

# WAL pages before an automatic checkpoint (page size is typically 4 kB, so
# 2000 pages ~= 8 MB of WAL — plenty for bursty ingest, tiny on disk).
WAL_AUTOCHECKPOINT_PAGES = int(os.environ.get("SOC_WAL_AUTOCHECKPOINT_PAGES", "2000"))
# How often the maintenance thread forces a truncating checkpoint.
WAL_MAINTENANCE_INTERVAL_SECONDS = int(os.environ.get("SOC_WAL_MAINTENANCE_SECONDS", "900"))
# Soft cap for the WAL file; a bigger file triggers an immediate checkpoint.
WAL_SOFT_MAX_BYTES = int(os.environ.get("SOC_WAL_SOFT_MAX_BYTES", str(64 * 1024 * 1024)))

_maintenance_thread: threading.Thread | None = None
# Clear = running. A separate shutdown event is used for sleep/wait so the
# maintenance loop actually sleeps between checkpoints (Event.wait returns
# immediately on a set event — using the running flag as the sleep gate
# turned this loop into a checkpoint spin-loop that starved the GIL).
_maintenance_running = threading.Event()
_shutdown = threading.Event()
_wal_path: str = ""


def apply_footprint_pragmas(conn: sqlite3.Connection) -> None:
    """Bound WAL growth and keep the page cache small on this connection."""
    conn.execute(f"PRAGMA wal_autocheckpoint={WAL_AUTOCHECKPOINT_PAGES}")
    # 2 MB page cache (negative = KiB). Default -2000 already means 2 MB;
    # set explicitly so the intent is visible and tunable in one place.
    conn.execute("PRAGMA cache_size=-2048")
    # Read hot pages directly from the OS page cache instead of copying them
    # into the SQLite cache — lower RSS for the 4.6 GB events database.
    conn.execute("PRAGMA mmap_size=268435456")  # 256 MB


def _wal_file_bytes() -> int:
    try:
        return os.path.getsize(_wal_path) if _wal_path else 0
    except OSError:
        return 0


def _maintenance_loop() -> None:
    while _maintenance_running.is_set():
        if _wal_path:
            wal_bytes = _wal_file_bytes()
            if wal_bytes > WAL_SOFT_MAX_BYTES:
                logger.info("WAL at %.1f MB exceeds soft cap — forcing truncating checkpoint",
                            wal_bytes / 1024 / 1024)
            else:
                logger.debug("WAL maintenance checkpoint (size %.1f MB)", wal_bytes / 1024 / 1024)
            try:
                # TRUNCATE checkpoints everything back into the main database and
                # shrinks the -wal file to zero bytes.
                conn = sqlite3.connect(_wal_path[:-4] if _wal_path.endswith("-wal") else _wal_path)
                try:
                    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
                finally:
                    conn.close()
            except sqlite3.Error as exc:
                logger.debug("WAL maintenance checkpoint skipped: %s", exc)
        if _shutdown.wait(WAL_MAINTENANCE_INTERVAL_SECONDS):
            break


def start_wal_maintenance(db_path: str | os.PathLike) -> None:
    """Start the periodic WAL truncation thread (no-op if already running)."""
    global _maintenance_thread, _wal_path
    _wal_path = str(db_path) + "-wal"
    if _maintenance_thread and _maintenance_thread.is_alive():
        return
    _maintenance_running.set()
    _shutdown.clear()
    _maintenance_thread = threading.Thread(
        target=_maintenance_loop, daemon=True, name="wal-maintenance"
    )
    _maintenance_thread.start()
    logger.info(
        "WAL maintenance started (interval=%ds, soft cap=%d MB)",
        WAL_MAINTENANCE_INTERVAL_SECONDS, WAL_SOFT_MAX_BYTES // (1024 * 1024),
    )


def stop_wal_maintenance() -> None:
    _maintenance_running.clear()
    _shutdown.set()
    if _maintenance_thread and _maintenance_thread.is_alive():
        _maintenance_thread.join(timeout=5)
