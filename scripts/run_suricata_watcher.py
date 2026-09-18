from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from app_shared.state_paths import state_path


PCAP_DIR = Path("ingest/pcap")
SURICATA_DIR = Path("ingest/suricata")
STATE_FILE = state_path("orchestration", "suricata_watcher.json")
EVE_TARGET = SURICATA_DIR / "eve.json"
WAZUH_EVE_TARGET = SURICATA_DIR / "fda-eve.jsonl"
# A malformed capture must not leave the suricata subprocess running forever.
PCAP_REPLAY_TIMEOUT = int(os.environ.get("FDA_PCAP_TIMEOUT_SECONDS", "120"))


def load_seen() -> set[str]:
    if not STATE_FILE.exists():
        return set()
    try:
        payload = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return set()
    return set(payload.get("seen", []))


def save_seen(seen: set[str]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps({"seen": sorted(seen)}, indent=2), encoding="utf-8")


def compact_wazuh_event(event: dict) -> dict | None:
    event_type = str(event.get("event_type") or "")
    if event_type not in {"flow", "alert", "http", "dns", "ssh", "tls"}:
        return None

    alert = event.get("alert") or {}
    flow = event.get("flow") or {}
    compact = {
        "fda_source": "suricata",
        "timestamp": event.get("timestamp"),
        "event_type": event_type,
        "src_ip": event.get("src_ip"),
        "src_port": event.get("src_port"),
        "dest_ip": event.get("dest_ip"),
        "dest_port": event.get("dest_port"),
        "proto": event.get("proto"),
        "flow_state": flow.get("state"),
        "alert_signature": alert.get("signature"),
        "alert_signature_id": alert.get("signature_id"),
    }
    compact["message"] = " ".join(
        str(value)
        for value in [
            "Suricata",
            event_type,
            compact["src_ip"],
            compact["dest_ip"],
            compact["dest_port"],
            compact["flow_state"],
            compact["alert_signature"],
        ]
        if value not in {None, ""}
    )
    return {key: value for key, value in compact.items() if value is not None}


def append_eve_lines(path: Path) -> int:
    if not path.exists():
        return 0
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return 0
    SURICATA_DIR.mkdir(parents=True, exist_ok=True)
    with EVE_TARGET.open("a", encoding="utf-8") as handle:
        for line in lines:
            handle.write(line)
            handle.write("\n")
    with WAZUH_EVE_TARGET.open("a", encoding="utf-8") as handle:
        for line in lines:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            compact = compact_wazuh_event(event)
            if compact:
                handle.write(json.dumps(compact, sort_keys=True))
                handle.write("\n")
    return len(lines)


def process_pcap(pcap_path: Path) -> int:
    run_dir = SURICATA_DIR / pcap_path.stem
    run_dir.mkdir(parents=True, exist_ok=True)
    command = [
        "suricata",
        "-r",
        str(pcap_path),
        "-l",
        str(run_dir),
        "-k",
        "none",
    ]
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, check=False, timeout=PCAP_REPLAY_TIMEOUT
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"suricata replay timed out after {PCAP_REPLAY_TIMEOUT}s") from exc
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "suricata replay failed")
    return append_eve_lines(run_dir / "eve.json")


def main() -> int:
    PCAP_DIR.mkdir(parents=True, exist_ok=True)
    SURICATA_DIR.mkdir(parents=True, exist_ok=True)
    EVE_TARGET.touch(exist_ok=True)
    WAZUH_EVE_TARGET.touch(exist_ok=True)
    seen = load_seen()

    while True:
        changed = False
        for pcap_path in sorted(PCAP_DIR.glob("*.pcap")):
            if pcap_path.name in seen:
                continue
            try:
                count = process_pcap(pcap_path)
                print(f"[suricata] processed {pcap_path.name} events={count}", flush=True)
                seen.add(pcap_path.name)
                changed = True
            except Exception as exc:  # noqa: BLE001
                print(f"[suricata] failed {pcap_path.name}: {exc}", flush=True)
        if changed:
            save_seen(seen)
        time.sleep(2)


if __name__ == "__main__":
    raise SystemExit(main())
