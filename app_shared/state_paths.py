"""Single source of truth for the runtime state written by this app.

Every process in the stack (API, response engine, orchestration engine, helper
scripts) reads and writes JSON/JSONL files under one directory:

    $SOC_STATE_DIR  (default: ./state; legacy $SOC_STATE_DIR still honored)

Keeping the location configurable means containers no longer have to guess, and
it removes the old behaviour where a process that could not write to `state/`
silently switched to `/tmp/fda-runtime` and split the data in half. Writes are
atomic (temp file + rename) and JSONL appends are locked, because the API and
the response watcher write the same files at the same time.
"""

from __future__ import annotations

import json
import os
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, Iterator

DEFAULT_STATE_DIR = "state"
# Where earlier versions stashed state when the configured directory was not writable.
LEGACY_FALLBACK_ROOT = Path("/tmp/fda-runtime")


def state_root() -> Path:
    """Directory that holds all runtime state for this deployment."""
    configured = (os.environ.get("SOC_STATE_DIR") or os.environ.get("SOC_STATE_DIR") or "").strip()
    return Path(configured) if configured else Path(DEFAULT_STATE_DIR)


def state_path(*parts: str) -> Path:
    """Path inside the configured state root."""
    return state_root().joinpath(*parts)


def ensure_parent(path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


@contextmanager
def _locked(target: Path) -> Iterator[IO[str]]:
    """Append to *target* while holding an advisory lock across processes."""
    ensure_parent(target)
    handle = target.open("a", encoding="utf-8")
    try:
        try:
            import fcntl

            fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        except (ImportError, OSError):
            # Locking is best effort; non-POSIX filesystems simply skip it.
            pass
        yield handle
    finally:
        handle.close()


def write_json(path: Path, payload: Any) -> None:
    """Atomically write JSON so readers never observe a half-written file."""
    ensure_parent(path)
    handle = tempfile.NamedTemporaryFile(
        "w",
        encoding="utf-8",
        dir=str(path.parent),
        prefix=f".{path.name}.",
        suffix=".tmp",
        delete=False,
    )
    try:
        with handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(handle.name, path)
    except BaseException:
        Path(handle.name).unlink(missing_ok=True)
        raise


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return default


def append_jsonl(path: Path, record: dict[str, Any]) -> Path:
    with _locked(path) as handle:
        handle.write(json.dumps(record, sort_keys=True, default=str))
        handle.write("\n")
    return path


def read_jsonl(path: Path, limit: int | None = None) -> list[dict[str, Any]]:
    try:
        raw_lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except OSError:
        return []
    if limit:
        raw_lines = raw_lines[-limit:]
    records: list[dict[str, Any]] = []
    for raw_line in raw_lines:
        if not raw_line.strip():
            continue
        try:
            row = json.loads(raw_line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            records.append(row)
    return records


def readable_candidates(path: Path) -> list[Path]:
    """*path* first, then the legacy locations the same artifact may live in.

    Older builds wrote to the in-repo `state/` directory, and fell back to
    `/tmp/fda-runtime` when that failed. Reading both keeps logs captured by
    those builds visible instead of looking like data loss.
    """
    candidates = [path]
    try:
        relative = path.relative_to(state_root())
    except ValueError:
        return candidates
    for legacy in (
        Path(DEFAULT_STATE_DIR) / relative,
        LEGACY_FALLBACK_ROOT / DEFAULT_STATE_DIR / relative,
    ):
        if legacy != path and legacy not in candidates:
            candidates.append(legacy)
    return candidates


def writable_path(path: Path) -> Path:
    """Return a path the caller can write to, creating its parent directory.

    Falls back to the legacy `/tmp/fda-runtime` location only when the configured
    state directory is genuinely not writable.
    """
    try:
        ensure_parent(path)
        if os.access(path.parent, os.W_OK):
            return path
    except OSError:
        pass
    try:
        relative = path.relative_to(state_root())
    except ValueError:
        relative = Path(path.name)
    fallback = LEGACY_FALLBACK_ROOT / DEFAULT_STATE_DIR / relative
    ensure_parent(fallback)
    return fallback
