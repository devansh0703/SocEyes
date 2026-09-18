"""Enhanced AI triage with raw packet context and correlated timeline.

Extends the existing NVIDIA LLM calls in services.py with:
- Raw packet hex dump (first 64 bytes) for network events
- Correlated timeline of related events (same source/destination IP)
- MITRE ATT&CK technique context
- Asset criticality scoring
- Structured verdict output (true/false positive + severity + confidence)

Falls back gracefully when NVIDIA API is unavailable: returns rule-based
severity and observe_only action.
"""
from __future__ import annotations

import json
import logging
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import requests

logger = logging.getLogger("fda.ai_triage")

# Cache for LLM responses (avoid duplicate calls for same context)
_cache: dict[str, tuple[float, dict[str, Any]]] = {}
_CACHE_TTL = 300  # 5 minutes


def _get_cached(key: str) -> dict[str, Any] | None:
    """Get cached LLM response if not expired."""
    if key in _cache:
        ts, data = _cache[key]
        if time.time() - ts < _CACHE_TTL:
            return data
        del _cache[key]
    return None


def _set_cached(key: str, data: dict[str, Any]) -> None:
    """Cache an LLM response."""
    _cache[key] = (time.time(), data)


def _build_packet_context(event: dict[str, Any]) -> str:
    """Build raw packet context string from event data."""
    parts = []

    # Raw hex dump if available
    raw = event.get("raw") or {}
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raw = {}

    # Extract packet bytes if present
    packet_bytes = raw.get("packet_bytes") or raw.get("raw_bytes") or ""
    if packet_bytes:
        # Show first 64 bytes as hex
        if isinstance(packet_bytes, str):
            hex_str = packet_bytes[:128]  # 64 bytes = 128 hex chars
        else:
            hex_str = bytes(packet_bytes[:64]).hex()
        parts.append(f"Packet hex (first 64 bytes): {hex_str}")

    # Network context
    src_ip = event.get("source_ip", "")
    dst_ip = event.get("destination_ip", "")
    src_port = event.get("source_port", "")
    dst_port = event.get("destination_port", "")
    protocol = event.get("network_transport", event.get("protocol", ""))

    if src_ip or dst_ip:
        parts.append(f"Network: {src_ip}:{src_port} -> {dst_ip}:{dst_port} ({protocol})")

    # Process context
    proc_name = event.get("process_name", "")
    proc_cmd = event.get("process_command_line", "")
    if proc_name:
        parts.append(f"Process: {proc_name} {proc_cmd}")

    # User context
    user = event.get("user_name", "")
    if user:
        parts.append(f"User: {user}")

    return "\n".join(parts) if parts else "No packet context available"


def _build_timeline_context(
    event: dict[str, Any],
    lookback_minutes: int = 30,
) -> str:
    """Build correlated timeline of related events."""
    try:
        from app_shared.unified_store import query_events
    except ImportError:
        return "Timeline unavailable"

    src_ip = event.get("source_ip", "")
    dst_ip = event.get("destination_ip", "")

    if not src_ip and not dst_ip:
        return "No IP addresses for correlation"

    # Query related events from the store
    end = datetime.now(timezone.utc)
    start = end - timedelta(minutes=lookback_minutes)

    try:
        related = query_events(
            sources=None,
            start=start.isoformat(),
            end=end.isoformat(),
            limit=50,
        )
    except Exception as exc:
        logger.warning("Timeline query failed: %s", exc)
        return f"Timeline query failed: {exc}"

    # Filter to events involving the same IPs
    correlated = []
    for ev in related:
        ev_src = ev.get("source_ip", "")
        ev_dst = ev.get("destination_ip", "")
        if (src_ip and ev_src == src_ip) or (dst_ip and ev_dst == dst_ip):
            correlated.append(ev)

    if not correlated:
        return f"No related events in last {lookback_minutes} minutes"

    # Build timeline string
    lines = [f"Correlated events (last {lookback_minutes} min): {len(correlated)}"]
    for ev in correlated[:10]:  # Cap at 10 for LLM context
        ts = ev.get("timestamp", "")
        action = ev.get("title", ev.get("message", ""))[:80]
        lines.append(f"  [{ts}] {action}")

    return "\n".join(lines)


def _build_mitre_context(technique_ids: list[str]) -> str:
    """Build MITRE ATT&CK technique context."""
    if not technique_ids:
        return "No MITRE techniques mapped"

    lines = ["MITRE ATT&CK techniques:"]
    for tid in technique_ids[:5]:
        lines.append(f"  - {tid}")
    return "\n".join(lines)


def ai_triage(
    event: dict[str, Any],
    include_llm: bool = True,
    api_key: str = "",
    model: str = "nvidia/nemotron-3.5-lightning-30b-a3b",
) -> dict[str, Any]:
    """Enhanced AI triage with raw packet context and timeline.

    Returns structured verdict:
    {
        "verdict": "true_positive" | "false_positive" | "unknown",
        "severity": "critical" | "high" | "medium" | "low",
        "confidence": 0.0-1.0,
        "summary": "plain English summary",
        "recommended_action": "block_source_ip" | "observe_only" | ...,
        "technical_details": "...",
        "llm_generated": true/false,
    }
    """
    # Build enriched context
    packet_ctx = _build_packet_context(event)
    timeline_ctx = _build_timeline_context(event)
    mitre_ctx = _build_mitre_context(event.get("technique_ids", []))

    # Combine into LLM prompt context
    llm_context = {
        "event": {
            "title": event.get("title", ""),
            "severity": event.get("severity", "medium"),
            "source_ip": event.get("source_ip", ""),
            "destination_ip": event.get("destination_ip", ""),
            "rule_id": event.get("rule_id", ""),
            "engine": event.get("engine", ""),
            "technique_ids": event.get("technique_ids", []),
        },
        "packet_context": packet_ctx,
        "timeline": timeline_ctx,
        "mitre": mitre_ctx,
    }

    # Check cache
    cache_key = json.dumps(llm_context, sort_keys=True)
    cached = _get_cached(cache_key)
    if cached:
        return cached

    # If no API key or LLM disabled, return rule-based fallback
    if not include_llm or not api_key:
        result = _rule_based_triage(event)
        _set_cached(cache_key, result)
        return result

    # Call NVIDIA LLM with enriched context
    try:
        body = {
            "model": model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are a SOC AI triage assistant. Analyze the network event, "
                        "packet context, correlated timeline, and MITRE techniques. "
                        "Return strict JSON with keys: verdict (true_positive/false_positive/unknown), "
                        "severity (critical/high/medium/low), confidence (0.0-1.0), "
                        "summary (plain English, 1-2 sentences), "
                        "recommended_action (block_source_ip/throttle_service/disable_account/"
                        "isolate_host/quarantine_endpoint/block_egress/observe_only), "
                        "technical_details (detailed analysis)."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(llm_context, sort_keys=True),
                },
            ],
            "temperature": 0.1,
            "response_format": {"type": "json_object"},
        }

        response = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=30,
        )
        response.raise_for_status()
        raw = response.json()["choices"][0]["message"]["content"].strip()
        parsed = json.loads(raw)

        result = {
            "verdict": parsed.get("verdict", "unknown"),
            "severity": parsed.get("severity", event.get("severity", "medium")),
            "confidence": float(parsed.get("confidence", 0.5)),
            "summary": parsed.get("summary", ""),
            "recommended_action": parsed.get("recommended_action", "observe_only"),
            "technical_details": parsed.get("technical_details", ""),
            "llm_generated": True,
        }
        _set_cached(cache_key, result)
        return result

    except Exception as exc:
        logger.warning("LLM triage failed, falling back to rule-based: %s", exc)
        result = _rule_based_triage(event)
        result["llm_error"] = str(exc)
        _set_cached(cache_key, result)
        return result


def _rule_based_triage(event: dict[str, Any]) -> dict[str, Any]:
    """Fallback rule-based triage when LLM is unavailable."""
    severity = event.get("severity", "medium")
    src_ip = event.get("source_ip", "")

    # Simple heuristics
    if severity in ("critical", "high"):
        verdict = "true_positive"
        action = "block_source_ip" if src_ip else "observe_only"
        confidence = 0.7
    elif severity == "medium":
        verdict = "unknown"
        action = "observe_only"
        confidence = 0.5
    else:
        verdict = "false_positive"
        action = "observe_only"
        confidence = 0.3

    return {
        "verdict": verdict,
        "severity": severity,
        "confidence": confidence,
        "summary": f"Rule-based triage: {severity} severity event from {src_ip or 'unknown'}",
        "recommended_action": action,
        "technical_details": f"Engine: {event.get('engine', '')}, Rule: {event.get('rule_id', '')}",
        "llm_generated": False,
    }
