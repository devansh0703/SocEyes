from __future__ import annotations

import argparse

from _common import emitters, repeat


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate live audit telemetry for Linux system info discovery")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    repeat(args.count, emitters.emit_sigma_system_info)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
