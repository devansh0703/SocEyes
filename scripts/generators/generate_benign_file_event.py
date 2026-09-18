from __future__ import annotations

import argparse

from _common import emitters, repeat


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate benign file-event control telemetry")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    repeat(args.count, emitters.emit_benign_file_event)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
