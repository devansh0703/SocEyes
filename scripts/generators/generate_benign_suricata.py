from __future__ import annotations

import argparse

from _common import emitters, repeat


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benign network flow control PCAP")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    repeat(args.count, emitters.emit_benign_suricata_pcap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
