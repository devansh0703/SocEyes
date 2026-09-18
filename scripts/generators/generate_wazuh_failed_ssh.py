from __future__ import annotations

import argparse

from _common import emitters, repeat


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate syslog failed SSH telemetry for Wazuh correlation")
    parser.add_argument("--count", type=int, default=1)
    args = parser.parse_args()
    repeat(args.count, emitters.emit_wazuh_failed_ssh)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
