from __future__ import annotations

import argparse
import os
import subprocess
from pathlib import Path


# Relative so the same invocation works inside the tools container
# (WORKDIR=/workspace) and on the host.
ROOT = Path(os.environ.get("PANTHER_ANALYSIS_ROOT", "panther-analysis"))


def ignored_files() -> list[str]:
    patterns = [
        ".vscode/schemas/*",
        ".github/**/*",
        "indexes/*",
        "packs/*.yml",
        "templates/*",
        "test_scenarios/**/*",
        "lookup_tables/okta/*.yml",
        "queries/gsuite_queries/gsuite_drive_many_docs_downloaded.yml",
    ]
    ignored: list[str] = []
    for pattern in patterns:
        ignored.extend(str(path) for path in ROOT.glob(pattern) if path.is_file())
    return sorted(set(ignored))


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Panther Analysis Tool tests")
    parser.add_argument("--path", default=str(ROOT), help="Path to Panther content to validate")
    args = parser.parse_args()
    root = Path(args.path)
    command = [
        "panther_analysis_tool",
        "test",
        "--path",
        str(root),
        "--show-failures-only",
    ]
    ignored = ignored_files() if root == ROOT else []
    if ignored:
        command.append("--ignore-files")
        command.extend(ignored)

    result = subprocess.run(command, check=False)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
