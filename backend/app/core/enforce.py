"""Real nftables enforcement for FDA Cyber Control.

Executes actual nftables commands to block IPs, throttle services,
isolate hosts, and cut egress. Every action carries a TTL and rolls back.

Mechanics
---------
* IP-based containment (block / isolate / egress) uses nftables **sets with
  the ``timeout`` flag**: enforcement adds one element with a timeout, and
  the kernel expires the element automatically. TTL rollback therefore
  survives process restarts and needs no external scheduler.
* ``throttle_service`` needs a per-IP rate, which a shared set cannot express,
  so it adds an accept-under-limit + drop-over-limit rule pair and rolls back
  by rule handle.
* A sweeper thread fires pending rollbacks at TTL (element delete / handle
  delete / account unlock), logs every transition, and persists pending
  entries to ``state/response/rollbacks.json`` so restarts never orphan them.

``EnforceAction`` owns validation and dry-run rendering; the individual
``enforce_*`` functions are live executors.

No mocks. No sample data. Real nftables rules verified with sudo.
"""
from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from app_shared.state_paths import read_json, state_path, write_json

logger = logging.getLogger("fda.enforce")

# nftables topology: one table, an input+output base chain, one timeout set
# per containment scope.
NFT_TABLE = "fda"
NFT_CHAIN = "fda_enforce"        # input hook (kept for backward compatibility)
NFT_OUTPUT_CHAIN = "fda_egress"  # output hook
NFT_SET = "fda_blocked_ips"      # kept for backward compatibility
NFT_SETS = {
    "blocked": "fda_blocked_ips",
    "isolated": "fda_isolated",
    "egress": "fda_egress_blocked",
}

# Default TTL for enforcement actions (seconds)
DEFAULT_TTL = 1800  # 30 minutes

_ROLLBACK_STATE_FILE = state_path("response", "rollbacks.json")
_ROLLBACK_SWEEP_INTERVAL = 15
_ROLLBACK_THREAD: threading.Thread | None = None
_ROLLBACK_RUNNING = threading.Event()

# Which policy field must be a valid IP, per action.
_IP_FIELD_BY_ACTION = {
    "block_source_ip": "source_ip",
    "throttle_service": "source_ip",
    "block_egress": "source_ip",
    "isolate_host": "destination_ip",
}


@dataclass
class EnforcementPolicy:
    """Policy for an enforcement action."""
    action: str  # block_source_ip, throttle_service, disable_account, isolate_host, block_egress
    source_ip: str = ""
    destination_ip: str = ""
    target_path: str = ""
    requests_per_minute: int = 0
    rule_id: str = ""
    technique_id: str = ""
    ttl_seconds: int = DEFAULT_TTL
    dry_run: bool = False
    log_file: str = ""


@dataclass
class EnforcementResult:
    """Result of an enforcement action."""
    success: bool
    action: str
    rule_id: str
    executed_command: str = ""
    error: str = ""
    dry_run: bool = False
    timestamp: str = ""
    ttl_seconds: int = 0
    rollback_at: str = ""


@dataclass
class PendingRollback:
    """A rollback the sweeper must execute once ``rollback_at`` passes."""
    kind: str  # "element" | "handle" | "command"
    rollback_at: float
    description: str
    payload: dict[str, Any] = field(default_factory=dict)
    log_file: str = ""

    def to_json(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "rollback_at": self.rollback_at,
            "description": self.description,
            "payload": self.payload,
            "log_file": self.log_file,
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> PendingRollback:
        return cls(
            kind=str(data.get("kind", "")),
            rollback_at=float(data.get("rollback_at", 0.0)),
            description=str(data.get("description", "")),
            payload=dict(data.get("payload") or {}),
            log_file=str(data.get("log_file", "")),
        )


# rule_id -> pending rollback (mirrored to disk for restart safety)
_active_rollbacks: dict[str, PendingRollback] = {}
_rollback_lock = threading.Lock()


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _rollback_at_iso(rollback_at: float) -> str:
    return datetime.fromtimestamp(rollback_at, tz=timezone.utc).isoformat()


def _run_nft(args: list[str], dry_run: bool = False) -> tuple[bool, str, str]:
    """Run an nftables command. Returns (success, stdout, stderr)."""
    cmd_str = " ".join(["sudo", "nft"] + args)
    if dry_run:
        logger.info("[DRY-RUN] Would execute: %s", cmd_str)
        return True, "", ""
    try:
        result = subprocess.run(["sudo", "nft"] + args, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            return True, result.stdout, ""
        return False, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "nft command timed out"
    except FileNotFoundError:
        return False, "", "nft not found (is nftables installed?)"
    except Exception as exc:
        return False, "", str(exc)


def _append_log(log_file: str, line: str) -> None:
    if not log_file:
        return
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with open(log_path, "a") as handle:
        handle.write(f"{_now_iso()} {line}\n")


# ---------------------------------------------------------------------------
# Rollback persistence + scheduling
# ---------------------------------------------------------------------------

def _persist_rollbacks() -> None:
    """Mirror pending rollbacks to disk so a restart never orphans them."""
    with _rollback_lock:
        snapshot = {rid: entry.to_json() for rid, entry in _active_rollbacks.items()}
    try:
        write_json(_ROLLBACK_STATE_FILE, snapshot)
    except OSError as exc:
        logger.warning("Could not persist rollbacks: %s", exc)


def _load_persisted_rollbacks() -> None:
    """Reload pending rollbacks written by a previous process."""
    stored = read_json(_ROLLBACK_STATE_FILE, default={})
    if not isinstance(stored, dict):
        return
    with _rollback_lock:
        for rule_id, entry in stored.items():
            if not isinstance(entry, dict) or rule_id in _active_rollbacks:
                continue
            try:
                _active_rollbacks[str(rule_id)] = PendingRollback.from_json(entry)
            except (TypeError, ValueError):
                continue
    if _active_rollbacks:
        logger.info("Restored %d pending rollback(s) from disk", len(_active_rollbacks))


def _schedule_rollback(entry: PendingRollback, rule_id: str) -> None:
    with _rollback_lock:
        _active_rollbacks[rule_id] = entry
    _persist_rollbacks()
    logger.info("Scheduled rollback for rule %s at %s", rule_id, _rollback_at_iso(entry.rollback_at))


def _rollback_already_gone(stderr: str) -> bool:
    lowered = (stderr or "").lower()
    return "no such file" in lowered or "does not exist" in lowered or "no such object" in lowered


def _execute_rollback(rule_id: str, entry: PendingRollback) -> bool:
    """Execute one rollback. Returns True when the target is gone either way."""
    ok = True
    err = ""
    if entry.kind == "element":
        ok, _, err = _run_nft([
            "delete", "element", "inet", NFT_TABLE,
            entry.payload.get("set_name", ""), "{", entry.payload.get("element", ""), "}",
        ])
    elif entry.kind == "handle":
        ok, _, err = _run_nft([
            "delete", "rule", "inet", NFT_TABLE,
            entry.payload.get("chain", NFT_CHAIN), "handle", str(entry.payload.get("handle", "")),
        ])
    elif entry.kind == "command":
        try:
            proc = subprocess.run(
                [str(a) for a in entry.payload.get("argv", [])],
                capture_output=True, text=True, timeout=10,
            )
            ok = proc.returncode == 0
            err = proc.stderr
        except Exception as exc:
            ok = False
            err = str(exc)

    # An element/handle that no longer exists was already rolled back
    # (the kernel TTL expired it): treat as success.
    if not ok and entry.kind != "command" and _rollback_already_gone(err):
        ok = True

    if ok:
        _append_log(entry.log_file, f"ROLLBACK_SUCCESS rule={rule_id} desc={entry.description}")
    else:
        _append_log(entry.log_file, f"ROLLBACK_FAILED rule={rule_id} desc={entry.description} err={err.strip()}")
    logger.info("Rollback for rule %s: ok=%s", rule_id, ok)
    return ok


def _rollback_loop() -> None:
    while _ROLLBACK_RUNNING.is_set():
        now = time.time()
        with _rollback_lock:
            due = [(rid, e) for rid, e in _active_rollbacks.items() if e.rollback_at <= now]
            for rid, _ in due:
                _active_rollbacks.pop(rid, None)
        retried = False
        for rule_id, entry in due:
            if _execute_rollback(rule_id, entry):
                _persist_rollbacks()
            else:
                entry.rollback_at = now + 60  # retry in a minute
                _schedule_rollback(entry, rule_id=rule_id)
                retried = True
        if not retried and not due:
            _persist_rollbacks()
        _ROLLBACK_RUNNING.wait(_ROLLBACK_SWEEP_INTERVAL)


def start_rollback_sweeper() -> None:
    """Start the background rollback sweeper (idempotent)."""
    global _ROLLBACK_THREAD
    if _ROLLBACK_THREAD and _ROLLBACK_THREAD.is_alive():
        return
    _load_persisted_rollbacks()
    _ROLLBACK_RUNNING.set()
    _ROLLBACK_THREAD = threading.Thread(target=_rollback_loop, daemon=True, name="enforce-rollback")
    _ROLLBACK_THREAD.start()
    logger.info("Rollback sweeper started")


def stop_rollback_sweeper() -> None:
    _ROLLBACK_RUNNING.clear()
    logger.info("Rollback sweeper stopped")


# ---------------------------------------------------------------------------
# Topology setup (idempotent)
# ---------------------------------------------------------------------------

_STATIC_RULES: tuple[tuple[str, list[str]], ...] = (
    (NFT_CHAIN, ["ip", "saddr", "@fda_blocked_ips", "drop"]),
    (NFT_CHAIN, ["ip", "saddr", "@fda_isolated", "drop"]),
    (NFT_CHAIN, ["ip", "daddr", "@fda_isolated", "drop"]),
    (NFT_OUTPUT_CHAIN, ["ip", "saddr", "@fda_egress_blocked", "drop"]),
)


def _ensure_nftables_setup() -> bool:
    """Create the fda table, chains, sets and static set-matching rules."""
    ok, _, err = _run_nft(["list", "table", "inet", NFT_TABLE])
    if not ok:
        ok, _, err = _run_nft(["add", "table", "inet", NFT_TABLE])
        if not ok:
            logger.error("Failed to create nftables table: %s", err)
            return False

    for chain, hook in ((NFT_CHAIN, "input"), (NFT_OUTPUT_CHAIN, "output")):
        ok, _, _ = _run_nft(["list", "chain", "inet", NFT_TABLE, chain])
        if not ok:
            ok, _, err = _run_nft([
                "add", "chain", "inet", NFT_TABLE, chain,
                "{", "type", "filter", "hook", hook, "priority", "0", ";", "}",
            ])
            if not ok:
                logger.error("Failed to create nftables chain %s: %s", chain, err)
                return False

    for set_name in NFT_SETS.values():
        ok, _, _ = _run_nft(["list", "set", "inet", NFT_TABLE, set_name])
        if not ok:
            ok, _, err = _run_nft([
                "add", "set", "inet", NFT_TABLE, set_name,
                "{", "type", "ipv4_addr", ";", "flags", "timeout", ";", "}",
            ])
            if not ok:
                logger.error("Failed to create nftables set %s: %s", set_name, err)
                return False

    for chain, rule_args in _STATIC_RULES:
        ok, stdout, _ = _run_nft(["list", "chain", "inet", NFT_TABLE, chain])
        if ok and " ".join(rule_args) in stdout.replace("\t", " "):
            continue
        ok, _, err = _run_nft(["add", "rule", "inet", NFT_TABLE, chain] + rule_args)
        if not ok:
            logger.error("Failed to add static rule %s: %s", " ".join(rule_args), err)
            return False

    return True


def _validate_ip(ip: str) -> bool:
    """Validate an IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


_self_ip_cache: set[str] | None = None


def _local_ips() -> set[str]:
    """Every IPv4 address configured on this machine's interfaces.

    getaddrinfo(hostname) only resolves /etc/hosts entries — it misses
    bridge IPs like docker0's 172.17.0.1. SIOCGIFCONF enumerates the real
    interface addresses from the kernel; plus the loopback range.
    """
    global _self_ip_cache
    if _self_ip_cache is not None:
        return _self_ip_cache
    addrs: set[str] = {"127.0.0.1"}
    try:
        import array
        import fcntl
        import socket
        import struct

        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        buf = array.array("B", b"\0" * 8192)
        result = fcntl.ioctl(
            s.fileno(), 0x8912,  # SIOCGIFCONF
            struct.pack("iL", 8192, buf.buffer_info()[0]),
        )
        outbytes = struct.unpack("iL", result)[0]
        raw = buf.tobytes()
        for off in range(0, outbytes, 40):
            addrs.add(socket.inet_ntoa(raw[off + 20 : off + 24]))
    except Exception as exc:  # pragma: no cover - non-Linux fallback
        logger.debug("SIOCGIFCONF enumeration failed: %s", exc)
    _self_ip_cache = addrs
    return addrs


def _is_self_ip(ip: str) -> bool:
    """True when ``ip`` is one of this machine's own addresses.

    Last line of defense against self-inflicted blackout: blocking the
    local host takes the API (and the rollback sweeper) down with it.
    The response engine should never auto-block the console itself.
    """
    if not ip:
        return False
    try:
        candidate = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if candidate.is_loopback:
        return True
    return str(candidate) in _local_ips()


# ---------------------------------------------------------------------------
# Set-based containment (block / isolate / egress)
# ---------------------------------------------------------------------------

def _enforce_set_element(
    action: str,
    set_name: str,
    ip: str,
    policy: EnforcementPolicy,
) -> EnforcementResult:
    """Contain ``ip`` by adding a timeout element to a set. Kernel TTL rolls back."""
    if _is_self_ip(ip):
        logger.warning("Refusing to enforce %s against this host itself (%s)", action, ip)
        return EnforcementResult(
            success=False,
            action=action,
            rule_id=policy.rule_id,
            error=f"Refusing to {action} the local host ({ip}) — self-protection",
            timestamp=_now_iso(),
        )
    if not _ensure_nftables_setup():
        return EnforcementResult(
            success=False,
            action=action,
            rule_id=policy.rule_id,
            error="Failed to setup nftables table/chains/sets",
            timestamp=_now_iso(),
        )

    add_args = ["add", "element", "inet", NFT_TABLE, set_name, "{", ip, "timeout", f"{policy.ttl_seconds}s", "}"]
    cmd_str = f"nft {' '.join(add_args)}"
    ok, stdout, err = _run_nft(add_args)
    if not ok:
        return EnforcementResult(
            success=False,
            action=action,
            rule_id=policy.rule_id,
            executed_command=cmd_str,
            error=err or stdout,
            timestamp=_now_iso(),
        )

    rollback_at = time.time() + policy.ttl_seconds
    rule_id = policy.rule_id or f"{action}:{set_name}:{ip}"
    _schedule_rollback(PendingRollback(
        kind="element",
        rollback_at=rollback_at,
        description=f"{action} {ip} via set {set_name}",
        payload={"set_name": set_name, "element": ip},
        log_file=policy.log_file,
    ), rule_id=rule_id)

    _append_log(policy.log_file, f"ENFORCE action={action} rule={rule_id} ip={ip} ttl={policy.ttl_seconds}")
    logger.info("Enforced %s for %s (set %s, TTL %ss)", action, ip, set_name, policy.ttl_seconds)
    return EnforcementResult(
        success=True,
        action=action,
        rule_id=rule_id,
        executed_command=cmd_str,
        timestamp=_now_iso(),
        ttl_seconds=policy.ttl_seconds,
        rollback_at=_rollback_at_iso(rollback_at),
    )


def enforce_block_source_ip(policy: EnforcementPolicy) -> EnforcementResult:
    """Block a source IP address using nftables (timeout set element)."""
    return _enforce_set_element("block_source_ip", NFT_SETS["blocked"], policy.source_ip, policy)


def enforce_block_egress(policy: EnforcementPolicy) -> EnforcementResult:
    """Block outbound traffic from a source IP (output chain + timeout set)."""
    return _enforce_set_element("block_egress", NFT_SETS["egress"], policy.source_ip, policy)


def enforce_isolate_host(policy: EnforcementPolicy) -> EnforcementResult:
    """Isolate a host by dropping all traffic to/from it (one set, two rules)."""
    return _enforce_set_element("isolate_host", NFT_SETS["isolated"], policy.destination_ip, policy)


# ---------------------------------------------------------------------------
# Rule-based throttle (per-IP rate => rule pair with handle rollback)
# ---------------------------------------------------------------------------

def _rule_handle(chain: str, rule_args: list[str]) -> str | None:
    """Find the nft handle of a rule previously added to ``chain``."""
    ok, stdout, _ = _run_nft(["-a", "list", "chain", "inet", NFT_TABLE, chain])
    if not ok:
        return None
    needle = " ".join(rule_args)
    for line in stdout.splitlines():
        normalized = line.strip().replace("\t", " ")
        if normalized.startswith(needle) and "# handle" in normalized:
            match = re.search(r"# handle (\d+)", normalized)
            if match:
                return match.group(1)
    return None


def enforce_throttle_service(policy: EnforcementPolicy) -> EnforcementResult:
    """Throttle a source IP: allow ``requests_per_minute``, drop the excess.

    Adds an accept-under-limit rule followed by a drop rule. Rolling back
    deletes both by handle.
    """
    if not _ensure_nftables_setup():
        return EnforcementResult(
            success=False,
            action="throttle_service",
            rule_id=policy.rule_id,
            error="Failed to setup nftables table/chains/sets",
            timestamp=_now_iso(),
        )

    accept_rule = ["ip", "saddr", policy.source_ip, "limit", "rate", f"{policy.requests_per_minute}/minute", "accept"]
    drop_rule = ["ip", "saddr", policy.source_ip, "drop"]
    cmd_str = (
        f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} {' '.join(accept_rule)}"
        f" && nft add rule inet {NFT_TABLE} {NFT_CHAIN} {' '.join(drop_rule)}"
    )

    for rule_args in (accept_rule, drop_rule):
        ok, stdout, err = _run_nft(["add", "rule", "inet", NFT_TABLE, NFT_CHAIN] + rule_args)
        if not ok:
            return EnforcementResult(
                success=False,
                action="throttle_service",
                rule_id=policy.rule_id,
                executed_command=cmd_str,
                error=err or stdout,
                timestamp=_now_iso(),
            )

    rollback_at = time.time() + policy.ttl_seconds
    rule_id = policy.rule_id or f"throttle_service:{policy.source_ip}:{policy.target_path}"
    for label, rule_args in (("accept", accept_rule), ("drop", drop_rule)):
        handle = _rule_handle(NFT_CHAIN, rule_args)
        if handle:
            _schedule_rollback(PendingRollback(
                kind="handle",
                rollback_at=rollback_at,
                description=f"throttle {policy.source_ip} ({label} rule)",
                payload={"chain": NFT_CHAIN, "handle": handle},
                log_file=policy.log_file,
            ), rule_id=f"{rule_id}:{label}")

    _append_log(policy.log_file, f"ENFORCE action=throttle_service rule={rule_id} ip={policy.source_ip} ttl={policy.ttl_seconds}")
    logger.info("Throttled %s to %s/minute (TTL %ss)", policy.source_ip, policy.requests_per_minute, policy.ttl_seconds)
    return EnforcementResult(
        success=True,
        action="throttle_service",
        rule_id=rule_id,
        executed_command=cmd_str,
        timestamp=_now_iso(),
        ttl_seconds=policy.ttl_seconds,
        rollback_at=_rollback_at_iso(rollback_at),
    )


# ---------------------------------------------------------------------------
# Account lockout
# ---------------------------------------------------------------------------

def enforce_disable_account(policy: EnforcementPolicy) -> EnforcementResult:
    """Disable a Linux account using usermod (not nftables)."""
    username = policy.source_ip  # the field is repurposed for the username
    cmd_str = f"usermod -L {username}"
    try:
        result = subprocess.run(["usermod", "-L", username], capture_output=True, text=True, timeout=10)
    except Exception as exc:
        return EnforcementResult(
            success=False,
            action="disable_account",
            rule_id=policy.rule_id,
            executed_command=cmd_str,
            error=str(exc),
            timestamp=_now_iso(),
        )
    if result.returncode != 0:
        return EnforcementResult(
            success=False,
            action="disable_account",
            rule_id=policy.rule_id,
            executed_command=cmd_str,
            error=result.stderr,
            timestamp=_now_iso(),
        )

    rollback_at = time.time() + policy.ttl_seconds
    rule_id = policy.rule_id or f"disable_account:{username}"
    _schedule_rollback(PendingRollback(
        kind="command",
        rollback_at=rollback_at,
        description=f"unlock account {username}",
        payload={"argv": ["usermod", "-U", username]},
        log_file=policy.log_file,
    ), rule_id=rule_id)

    _append_log(policy.log_file, f"ENFORCE action=disable_account rule={rule_id} user={username} ttl={policy.ttl_seconds}")
    return EnforcementResult(
        success=True,
        action="disable_account",
        rule_id=rule_id,
        executed_command=cmd_str,
        timestamp=_now_iso(),
        ttl_seconds=policy.ttl_seconds,
        rollback_at=_rollback_at_iso(rollback_at),
    )


# ---------------------------------------------------------------------------
# Dispatch: validation + dry-run live here; executors below are live-only.
# ---------------------------------------------------------------------------

def _validate_policy(policy: EnforcementPolicy) -> str:
    """Return an error message for invalid policies, or "" when valid."""
    ip_field = _IP_FIELD_BY_ACTION.get(policy.action)
    if ip_field:
        ip = getattr(policy, ip_field)
        if not _validate_ip(ip):
            return f"Invalid IP address: {ip}"
    if policy.action == "throttle_service" and policy.requests_per_minute <= 0:
        return "requests_per_minute must be > 0"
    if policy.action == "disable_account":
        username = policy.source_ip
        if not username or username.startswith("-"):
            return "disable_account requires a valid username"
    return ""


def _preview_command(policy: EnforcementPolicy) -> str:
    """Generate a preview of the command without executing it."""
    if policy.action == "block_source_ip":
        return f"nft add element inet {NFT_TABLE} {NFT_SETS['blocked']} {{ {policy.source_ip} timeout {policy.ttl_seconds}s }}"
    if policy.action == "block_egress":
        return f"nft add element inet {NFT_TABLE} {NFT_SETS['egress']} {{ {policy.source_ip} timeout {policy.ttl_seconds}s }}"
    if policy.action == "throttle_service":
        return (
            f"nft add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr {policy.source_ip} "
            f"limit rate {policy.requests_per_minute}/minute accept"
            f" && nft add rule inet {NFT_TABLE} {NFT_CHAIN} ip saddr {policy.source_ip} drop"
        )
    if policy.action == "isolate_host":
        return f"nft add element inet {NFT_TABLE} {NFT_SETS['isolated']} {{ {policy.destination_ip} timeout {policy.ttl_seconds}s }}"
    if policy.action == "disable_account":
        return f"usermod -L {policy.source_ip}"
    return f"# unknown action: {policy.action}"


def EnforceAction(policy: EnforcementPolicy) -> EnforcementResult:
    """Dispatch an enforcement action based on policy type."""
    error = _validate_policy(policy)
    if error:
        return EnforcementResult(
            success=False,
            action=policy.action,
            rule_id=policy.rule_id,
            error=error,
            timestamp=_now_iso(),
        )

    if policy.dry_run:
        cmd = _preview_command(policy)
        logger.info("[DRY-RUN] Would execute: %s", cmd)
        _append_log(policy.log_file, f"DRY_RUN action={policy.action} rule={policy.rule_id} cmd={cmd}")
        return EnforcementResult(
            success=True,
            action=policy.action,
            rule_id=policy.rule_id,
            executed_command=cmd,
            dry_run=True,
            timestamp=_now_iso(),
            ttl_seconds=policy.ttl_seconds,
        )

    dispatch = {
        "block_source_ip": enforce_block_source_ip,
        "throttle_service": enforce_throttle_service,
        "isolate_host": enforce_isolate_host,
        "disable_account": enforce_disable_account,
        "block_egress": enforce_block_egress,
    }
    handler = dispatch.get(policy.action)
    if handler is None:
        return EnforcementResult(
            success=False,
            action=policy.action,
            rule_id=policy.rule_id,
            error=f"Unknown enforcement action: {policy.action}",
            timestamp=_now_iso(),
        )
    return handler(policy)
