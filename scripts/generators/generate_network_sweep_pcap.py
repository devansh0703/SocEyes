from __future__ import annotations

import argparse

from _common import emitters, repeat


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate a PCAP network sweep for Suricata and Elastic validation")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    repeat(args.count, emitters.emit_suricata_network_sweep_pcap)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
