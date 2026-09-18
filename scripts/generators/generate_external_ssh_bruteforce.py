from __future__ import annotations

import argparse

from _common import emitters, repeat


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate repeated failed SSH authentication telemetry")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    repeat(args.count, emitters.emit_elastic_external_ssh_bruteforce)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
