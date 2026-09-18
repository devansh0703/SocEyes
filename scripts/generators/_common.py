from __future__ import annotations

import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# `emitters` is re-exported on purpose: every generator does
# `from _common import emitters, repeat`.
from scripts.manual_rules import emit_existing_rule_signals as emitters  # noqa: E402,F401


def repeat(count: int, fn) -> None:
    for _ in range(max(1, count)):
        fn()
