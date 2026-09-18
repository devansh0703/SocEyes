from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_shared.state_paths import append_jsonl, state_path


STATE_DIR = state_path("honeypot")
SESSIONS_FILE = STATE_DIR / "sessions.jsonl"
NVIDIA_API_KEY = os.environ.get("NVIDIA_API_KEY", "").strip()
NVIDIA_MODEL = os.environ.get("NVIDIA_MODEL", "nvidia/nemotron-3.5-lightning-30b-a3b")

HONEYPOT_IMAGE = os.environ.get("HONEYPOT_IMAGE", "python:3.11-slim")
# A honeypot must never be able to exhaust the host: hard caps on memory, CPU and
# process count, a read-only root filesystem, and no ability to gain privileges.
HONEYPOT_MEMORY_LIMIT = os.environ.get("HONEYPOT_MEMORY_LIMIT", "128m")
HONEYPOT_CPU_LIMIT = os.environ.get("HONEYPOT_CPU_LIMIT", "0.25")
HONEYPOT_PIDS_LIMIT = os.environ.get("HONEYPOT_PIDS_LIMIT", "64")
# Containers are reaped once they are older than this (0 disables reaping).
HONEYPOT_TTL_SECONDS = int(os.environ.get("HONEYPOT_TTL_SECONDS", "900"))
# Loopback by default. Set HONEYPOT_BIND_ADDRESS=0.0.0.0 only when the trap is
# deliberately internet-facing.
HONEYPOT_BIND_ADDRESS = os.environ.get("HONEYPOT_BIND_ADDRESS", "127.0.0.1")
HONEYPOT_LABEL = "fda.honeypot=true"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def clean_name(value: str) -> str:
    sanitized = re.sub(r"[^a-zA-Z0-9_.-]", "-", value or "")
    return sanitized.strip("-")[:40] or "unknown"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deploy a sandboxed docker honeypot and capture analysis artifacts")
    parser.add_argument("--source-ip", default="")
    parser.add_argument("--rule-id", default="")
    parser.add_argument("--technique-id", default="")
    parser.add_argument("--engine", default="")
    parser.add_argument("--severity", default="unknown")
    parser.add_argument("--message", default="")
    parser.add_argument(
        "--ttl-seconds",
        type=int,
        default=HONEYPOT_TTL_SECONDS,
        help="reap honeypot containers older than this (0 disables reaping)",
    )
    parser.add_argument("--bind-address", default=HONEYPOT_BIND_ADDRESS)
    return parser.parse_args()


def run_command(command: list[str], timeout: int = 120) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(command, capture_output=True, text=True, check=False, timeout=timeout)
    except subprocess.TimeoutExpired:
        return subprocess.CompletedProcess(command, returncode=124, stdout="", stderr="docker command timed out")


def parse_docker_timestamp(value: str) -> datetime | None:
    """Docker returns RFC3339 with nanosecond precision; trim it to microseconds."""
    cleaned = re.sub(r"(\.\d{6})\d+", r"\1", (value or "").strip())
    if not cleaned:
        return None
    try:
        return datetime.fromisoformat(cleaned.replace("Z", "+00:00"))
    except ValueError:
        return None


def reap_expired_honeypots(ttl_seconds: int) -> list[str]:
    """Remove honeypot containers that outlived *ttl_seconds*.

    Honeypots are long-lived `docker run -d` containers. Without this they pile up
    forever - each one holding memory and a host port - and the only way to clean
    them up was to remember `docker rm` by hand.
    """
    if ttl_seconds <= 0:
        return []
    listed = run_command(["docker", "ps", "-aq", "--filter", f"label={HONEYPOT_LABEL}"], timeout=30)
    container_ids = listed.stdout.split() if listed.returncode == 0 else []
    if not container_ids:
        return []
    inspected = run_command(
        ["docker", "inspect", "--format", "{{.Id}} {{.State.StartedAt}}", *container_ids],
        timeout=60,
    )
    if inspected.returncode != 0:
        return []
    now = datetime.now(timezone.utc)
    expired: list[str] = []
    for line in inspected.stdout.splitlines():
        parts = line.split()
        if len(parts) != 2:
            continue
        started_at = parse_docker_timestamp(parts[1])
        if started_at and (now - started_at).total_seconds() > ttl_seconds:
            expired.append(parts[0])
    if expired:
        run_command(["docker", "rm", "-f", *expired], timeout=120)
    return expired


def honeypot_server_code() -> str:
    return (
        "import json, socketserver, datetime, pathlib;"
        "path=pathlib.Path('/data/traffic.jsonl');"
        "path.parent.mkdir(parents=True, exist_ok=True);"
        "class H(socketserver.BaseRequestHandler):\n"
        "  def handle(self):\n"
        "    data=self.request.recv(4096)\n"
        "    rec={'timestamp':datetime.datetime.utcnow().isoformat()+'Z','client':self.client_address[0],'port':self.client_address[1],'bytes':len(data),'payload_preview':data[:120].decode('utf-8','ignore')}\n"
        "    with path.open('a', encoding='utf-8') as f: f.write(json.dumps(rec)+'\\n')\n"
        "    self.request.sendall(b'SSH-2.0-OpenSSH_8.9p1 Debian-3\\r\\n')\n"
        "socketserver.ThreadingTCPServer.allow_reuse_address=True;"
        "srv=socketserver.ThreadingTCPServer(('0.0.0.0', 2222), H);"
        "srv.serve_forever()"
    )


def collect_nvidia_analysis(session: dict[str, Any], docker_logs: str, traffic_lines: list[dict[str, Any]]) -> str:
    if not NVIDIA_API_KEY:
        return ""
    body = {
        "model": NVIDIA_MODEL,
        "messages": [
            {
                "role": "system",
                "content": "You analyze honeypot telemetry. Return concise actionable SOC analysis with attacker behavior, risk, and next containment steps.",
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "session": session,
                        "docker_logs": docker_logs[-4000:],
                        "traffic_samples": traffic_lines[:50],
                    },
                    sort_keys=True,
                ),
            },
        ],
        "temperature": 0.1,
    }
    try:
        response = requests.post(
            "https://integrate.api.nvidia.com/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {NVIDIA_API_KEY}",
                "Content-Type": "application/json",
            },
            json=body,
            timeout=30,
        )
        response.raise_for_status()
        return str(response.json()["choices"][0]["message"]["content"]).strip()
    except Exception:
        return ""


def main() -> int:
    args = parse_args()

    reaped = reap_expired_honeypots(args.ttl_seconds)
    if reaped:
        print(f"[honeypot] reaped {len(reaped)} expired container(s)", flush=True)

    session_id = f"hp-{datetime.now(timezone.utc):%Y%m%dT%H%M%SZ}-{clean_name(args.source_ip)}"
    session_dir = STATE_DIR / "sessions" / session_id
    session_dir.mkdir(parents=True, exist_ok=True)
    container_name = clean_name(session_id)

    run = run_command(
        [
            "docker",
            "run",
            "-d",
            "--name",
            container_name,
            "--label",
            HONEYPOT_LABEL,
            "--label",
            f"fda.session_id={session_id}",
            # Hard limits so the trap cannot be turned against the host.
            "--memory",
            HONEYPOT_MEMORY_LIMIT,
            "--cpus",
            HONEYPOT_CPU_LIMIT,
            "--pids-limit",
            HONEYPOT_PIDS_LIMIT,
            "--security-opt",
            "no-new-privileges",
            "--read-only",
            "--tmpfs",
            "/tmp:rw,noexec,nosuid,size=16m",
            "--user",
            f"{os.getuid()}:{os.getgid()}",
            "-e",
            "HOME=/tmp",
            # Loopback by default: never expose the trap to the world by accident.
            "-p",
            f"{args.bind_address}:0:2222",
            "-v",
            f"{session_dir.resolve()}:/data",
            HONEYPOT_IMAGE,
            "python",
            "-u",
            "-c",
            honeypot_server_code(),
        ]
    )
    if run.returncode != 0:
        print(run.stderr.strip() or run.stdout.strip() or "failed to start honeypot", flush=True)
        return 1

    container_id = run.stdout.strip()
    time.sleep(1.5)

    port_result = run_command(["docker", "port", container_name, "2222/tcp"])
    host_port = ""
    if port_result.returncode == 0:
        value = port_result.stdout.strip()
        if ":" in value:
            host_port = value.split(":")[-1]

    logs_result = run_command(["docker", "logs", "--tail", "200", container_name])
    docker_logs = (logs_result.stdout or "") + (logs_result.stderr or "")
    (session_dir / "docker.log").write_text(docker_logs, encoding="utf-8")

    traffic_items: list[dict[str, Any]] = []
    traffic_path = session_dir / "traffic.jsonl"
    if traffic_path.exists():
        for line in traffic_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            try:
                traffic_items.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    payload = {
        "session_id": session_id,
        "created_at": now_iso(),
        "container_name": container_name,
        "container_id": container_id,
        "host_port": host_port,
        "source_ip": args.source_ip,
        "rule_id": args.rule_id,
        "technique_id": args.technique_id,
        "engine": args.engine,
        "severity": args.severity,
        "message": args.message,
        "log_path": str((session_dir / "docker.log").resolve()),
        "traffic_path": str(traffic_path.resolve()),
        "events_captured": len(traffic_items),
    }

    analysis = collect_nvidia_analysis(payload, docker_logs, traffic_items)
    if analysis:
        payload["nvidia_analysis"] = analysis

    payload["ttl_seconds"] = args.ttl_seconds
    payload["bind_address"] = args.bind_address
    (session_dir / "session.json").write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
    append_jsonl(SESSIONS_FILE, payload)

    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
