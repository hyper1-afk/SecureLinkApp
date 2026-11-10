from __future__ import annotations

import subprocess
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
GOOGLE_API_KEY_PATTERN = r"AIza[0-9A-Za-z_-]{35}"


def main() -> int:
    result = subprocess.run(
        [
            "git",
            "log",
            "--all",
            "--format=%H",
            "-G",
            GOOGLE_API_KEY_PATTERN,
            "--",
        ],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        print("Unable to audit Git history for Google API key patterns.")
        return result.returncode

    commits = sorted(set(result.stdout.splitlines()))
    if commits:
        print(
            "Historical Google API key-shaped values remain in Git history; "
            "values are suppressed. Review these commits and invalidate exposed keys:"
        )
        for commit in commits:
            print(commit)
        return 1

    print("No historical Google API key patterns found on fetched Git refs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
