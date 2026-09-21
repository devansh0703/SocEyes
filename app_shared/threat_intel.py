"""Threat-intel indicator store and feed synchronization.

Makes the enrich-index class of Elastic rules live: rules like
``Threat Intel IP Address Indicator Match`` join events against a threat
indicator index. This module provides that index:

- ``indicators`` table in the unified store: type, value, feed, severity,
  first/last seen, hit counts
- feed sync from URL lists (abuse.ch URLhaus/feodo, CIArmy) and local files,
  plus a builtin demo set so the pipeline works offline
- ``lookup_ip`` / ``lookup_domain`` / ``lookup_url`` / ``lookup_hash`` for the
  rule engine, ``record_hits`` for feedback (indicator hit counts feed the
  coverage report)

Feed URLs and the demo set can be overridden via env:
``SOC_TI_FEEDS`` (comma-separated URLs or file:// paths, empty = builtin only)
``SOC_TI_SYNC_SEC`` (refresh interval, default 6h)
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import sqlite3
import threading
import time
from typing import Any

from app_shared.unified_store import _now_iso, get_conn

logger = logging.getLogger(__name__)

_ti_lock = threading.Lock()
_last_sync = 0.0


def _env(name: str, default: str) -> str:
    # SOC_* wins; SOC_* kept as the pre-rebrand fallback.
    return os.environ.get(name) or os.environ.get(name.replace("SOC_", "SOC_", 1)) or default


# Builtin bootstrap feed: well-documented sinkhole/test indicators so the
# enrich pipeline demonstrably works with zero external dependencies.
_BUILTIN_FEED = "soc-eyes-builtin"
_BUILTIN_INDICATORS = [
    # TEST-NET-3 documentation ranges + benchmark malware sim hosts.
    # These are RFC 5737 / RFC 2606 reserved — safe to treat as malicious.
    {"type": "ip", "value": "203.0.113.66", "severity": "high", "comment": "builtin testnet3 c2"},
    {"type": "ip", "value": "203.0.113.99", "severity": "critical", "comment": "builtin testnet3 exfil host"},
    {"type": "ip", "value": "198.51.100.23", "severity": "high", "comment": "builtin testnet2 c2"},
    {"type": "domain", "value": "malware.example", "severity": "high", "comment": "builtin demo malware domain"},
    {"type": "domain", "value": "c2.badrepo.example", "severity": "critical", "comment": "builtin demo c2 repo domain"},
    {"type": "url", "value": "http://malware.example/payload.sh", "severity": "high", "comment": "builtin demo payload url"},
    {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "severity": "medium", "comment": "empty-file sha256 (canary)"},
]

# Public feeds: one indicator per line, '#' comments allowed.
# Lines are auto-typed: IP -> ip, hostname-like -> domain, scheme:// -> url,
# 64-hex -> sha256, 32-hex -> md5.
_DEFAULT_FEED_URLS = [
    "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
    "https://urlhaus.abuse.ch/downloads/host/",
]


def init_ti_schema(con: sqlite3.Connection | None = None) -> None:
    """Create the indicators table if missing."""
    own = con is None
    con = con or get_conn()
    con.execute(
        """
        CREATE TABLE IF NOT EXISTS indicators (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            type TEXT NOT NULL,
            value TEXT NOT NULL,
            feed TEXT NOT NULL DEFAULT '',
            severity TEXT NOT NULL DEFAULT 'medium',
            comment TEXT NOT NULL DEFAULT '',
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            hit_count INTEGER NOT NULL DEFAULT 0,
            UNIQUE(type, value)
        )
        """
    )
    con.execute("CREATE INDEX IF NOT EXISTS idx_indicators_value ON indicators(type, value)")
    con.commit()
    if own and hasattr(con, "close"):
        pass  # shared connection; do not close


def _classify(line: str) -> tuple[str, str] | None:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
        return ("sha256", line.lower())
    if len(line) == 32 and all(c in "0123456789abcdefABCDEF" for c in line):
        return ("md5", line.lower())
    if "://" in line:
        return ("url", line)
    try:
        ipaddress.ip_address(line)
        return ("ip", line)
    except ValueError:
        pass
    if "." in line and " " not in line:
        return ("domain", line.lower())
    return None


def _parse_feed_text(text: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for line in text.splitlines():
        c = _classify(line)
        if c:
            out.append(c)
    return out


def _sync_builtin(con: sqlite3.Connection) -> int:
    now = _now_iso()
    n = 0
    for ind in _BUILTIN_INDICATORS:
        con.execute(
            """
            INSERT INTO indicators (type, value, feed, severity, comment, first_seen, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(type, value) DO UPDATE SET last_seen = excluded.last_seen
            """,
            (ind["type"], ind["value"], _BUILTIN_FEED, ind["severity"], ind["comment"], now, now),
        )
        n += 1
    con.commit()
    return n


def sync_feeds(force: bool = False) -> dict[str, int]:
    """Sync all configured feeds into the indicator store. Safe to call often."""
    global _last_sync
    interval = int(_env("SOC_TI_SYNC_SEC", "21600"))
    now = time.time()
    if not force and (now - _last_sync) < interval:
        return {}

    with _ti_lock:
        try:
            init_ti_schema()
            con = get_conn()
            added = _sync_builtin(con)

            feeds = [u.strip() for u in _env("SOC_TI_FEEDS", "").split(",") if u.strip()]
            if not feeds:
                if _env("SOC_TI_FEEDS", "") == "" and _env("SOC_TI_DEFAULT_PUBLIC_FEEDS", "1") != "0":
                    feeds = list(_DEFAULT_FEED_URLS)

            for url in feeds:
                try:
                    text = _fetch_feed(url)
                    pairs = _parse_feed_text(text)
                    now_iso = _now_iso()
                    for typ, val in pairs[:50000]:  # cap per feed
                        con.execute(
                            """
                            INSERT INTO indicators (type, value, feed, severity, comment, first_seen, last_seen)
                            VALUES (?, ?, ?, 'medium', ?, ?, ?)
                            ON CONFLICT(type, value) DO UPDATE SET last_seen = excluded.last_seen
                            """,
                            (typ, val, url, f"feed: {url}", now_iso, now_iso),
                        )
                    con.commit()
                    logger.info("TI feed %s synced: %d indicators", url, len(pairs))
                except Exception as exc:
                    logger.warning("TI feed %s failed: %s", url, exc)

            _last_sync = now
            total = con.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
            logger.info("Threat intel store synced: %d indicators total", total)
            return {"total": total, "builtin": added}
        except Exception as exc:
            logger.warning("TI sync failed: %s", exc)
            return {}


def _fetch_feed(url: str) -> str:
    if url.startswith("file://"):
        with open(url[7:], "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    import requests

    r = requests.get(url, timeout=20)
    r.raise_for_status()
    return r.text


def _load_maps() -> dict[str, dict[str, dict[str, Any]]]:
    """Build per-type {value: indicator} maps. Small stores; rebuilt per pass."""
    init_ti_schema()
    con = get_conn()
    rows = con.execute("SELECT type, value, severity, feed, comment FROM indicators").fetchall()
    maps: dict[str, dict[str, dict[str, Any]]] = {"ip": {}, "domain": {}, "url": {}, "sha256": {}, "md5": {}}
    for r in rows:
        t = r["type"]
        if t in maps:
            maps[t][r["value"]] = dict(r)
    return maps


_maps_cache: tuple[float, dict[str, dict[str, dict[str, Any]]]] | None = None
_maps_lock = threading.Lock()


def _maps() -> dict[str, dict[str, dict[str, Any]]]:
    global _maps_cache
    with _maps_lock:
        if _maps_cache is None or time.time() - _maps_cache[0] > 300:
            _maps_cache = (time.time(), _load_maps())
        return _maps_cache[1]


def refresh_maps() -> None:
    """Force map rebuild (after a manual sync)."""
    global _maps_cache
    with _maps_lock:
        _maps_cache = None


def lookup_ip(ip: str) -> dict[str, Any] | None:
    return _maps().get("ip", {}).get(str(ip).strip())


def lookup_domain(domain: str) -> dict[str, Any] | None:
    d = str(domain).strip().lower().rstrip(".")
    return _maps().get("domain", {}).get(d)


def lookup_url(url: str) -> dict[str, Any] | None:
    u = str(url).strip()
    m = _maps().get("url", {})
    if u in m:
        return m[u]
    # host-extraction fallback: domain feed covers urls pointing at known hosts
    try:
        from urllib.parse import urlparse

        host = urlparse(u).hostname or ""
        return lookup_domain(host)
    except Exception:
        return None


def lookup_hash(h: str) -> dict[str, Any] | None:
    h = str(h).strip().lower()
    return _maps().get("sha256", {}).get(h) or _maps().get("md5", {}).get(h)


def record_hits(kind: str, values: list[str], n: int = 1) -> None:
    """Increment hit_count for matched indicators (feedback for coverage)."""
    if not values:
        return
    try:
        init_ti_schema()
        con = get_conn()
        with _ti_lock:
            con.execute(
                f"UPDATE indicators SET hit_count = hit_count + ? WHERE type = ? AND value IN ({','.join('?' * len(values))})",
                (n, kind, *[v.lower() if kind in ("domain", "sha256", "md5") else v for v in values]),
            )
            con.commit()
    except Exception as exc:
        logger.debug("record_hits failed: %s", exc)


def ti_stats() -> dict[str, Any]:
    try:
        init_ti_schema()
        con = get_conn()
        total = con.execute("SELECT COUNT(*) FROM indicators").fetchone()[0]
        by_type = dict(con.execute("SELECT type, COUNT(*) FROM indicators GROUP BY type").fetchall())
        by_feed = dict(con.execute("SELECT feed, COUNT(*) FROM indicators GROUP BY feed").fetchall())
        hits = con.execute("SELECT COALESCE(SUM(hit_count), 0) FROM indicators").fetchone()[0]
        return {"total": total, "by_type": by_type, "by_feed": by_feed, "hits": hits,
                "feeds_configured": len([u for u in _env("SOC_TI_FEEDS", "").split(",") if u.strip()]) or len(_DEFAULT_FEED_URLS)}
    except Exception as exc:
        return {"error": str(exc), "total": 0}
