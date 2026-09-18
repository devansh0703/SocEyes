"""Shared Elasticsearch / Kibana HTTP client factory.

Consolidates the three previously duplicated session factories that lived in
``scripts/common.py``, ``backend/app/services.py`` and
``scripts/run_orchestration_engine.py``.

The factory returns a *shared*, connection-pooled ``requests.Session`` so that
every call reuses the same TCP connection pool instead of opening a fresh
socket on every request — the old behaviour leaked sockets and inflated memory
usage under load.
"""
from __future__ import annotations

import os
import threading

import requests

# ---------------------------------------------------------------------------
# Configuration (read once from the environment at import time)
# ---------------------------------------------------------------------------
ELASTICSEARCH_URL = os.environ.get(
    "ELASTICSEARCH_URL", "http://localhost:9201"
).rstrip("/")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5602").rstrip("/")
ELASTIC_PASSWORD = os.environ.get("ELASTIC_PASSWORD", "")
ELASTIC_USER = os.environ.get("ELASTIC_USER", "elastic")


def _make_pooled_session(extra_headers: dict[str, str] | None = None) -> requests.Session:
    """Create a ``requests.Session`` with auth, JSON headers and an HTTPAdapter pool."""
    client = requests.Session()
    client.auth = (ELASTIC_USER, ELASTIC_PASSWORD)
    client.headers.update({"Content-Type": "application/json"})
    if extra_headers:
        client.headers.update(extra_headers)
    adapter = requests.adapters.HTTPAdapter(pool_connections=10, pool_maxsize=20)
    client.mount("http://", adapter)
    client.mount("https://", adapter)
    return client


# ---------------------------------------------------------------------------
# Lazy singletons
# ---------------------------------------------------------------------------
_es_lock = threading.Lock()
_es_session: requests.Session | None = None

_kb_lock = threading.Lock()
_kb_session: requests.Session | None = None


def get_es_client() -> requests.Session:
    """Return the process-wide, pooled Elasticsearch session (lazy singleton)."""
    global _es_session
    with _es_lock:
        if _es_session is None:
            _es_session = _make_pooled_session()
        return _es_session


def get_kibana_client() -> requests.Session:
    """Return the process-wide, pooled Kibana session (lazy singleton)."""
    global _kb_session
    with _kb_lock:
        if _kb_session is None:
            _kb_session = _make_pooled_session({"kbn-xsrf": "true"})
        return _kb_session


# ---------------------------------------------------------------------------
# Backwards-compatible aliases
#
# Existing modules do ``from common import elastic_session`` or
# ``from run_orchestration_engine import elastic_session``.  Pointing those
# names at the shared factory means every caller automatically gets the pooled
# singleton without changing a single call-site.
# ---------------------------------------------------------------------------
elastic_session = get_es_client
kibana_session = get_kibana_client
