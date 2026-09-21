"""Shared filesystem anchors for the backend package."""
from __future__ import annotations

from pathlib import Path

# Repository root (the repository directory containing backend/, app_shared/, state/...)
_ROOT = Path(__file__).resolve().parent.parent.parent
