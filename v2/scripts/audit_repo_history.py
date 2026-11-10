from __future__ import annotations

import re
import subprocess
from pathlib import Path


REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
SECRET_PATTERNS = {
    "Google API key": r"AIza[0-9A-Za-z_-]{35}",
    "AWS access key ID": r"AKIA[0-9A-Z]{16}",
    "GitHub access token": r"gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,}",
    "Slack token": r"xox[baprs]-[A-Za-z0-9-]{20,}",
    "Stripe secret key": r"(sk|rk)_(live|test)_[A-Za-z0-9]{12,}",
    "Google OAuth client secret": r"GOCSPX-[A-Za-z0-9_-]{20,}",
    "SendGrid API key": r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    "NPM access token": r"npm_[A-Za-z0-9]{36}",
    "Private key material": r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----",
}
SENSITIVE_PATH = re.compile(
    r"(^|/)(\.env(?:\.[^/]+)?|id_rsa|id_ed25519|credentials\.json|"
    r"service-account[^/]*\.json|[^/]+\.(?:pem|p12|pfx|key|jks))$",
    re.IGNORECASE,
)


def commits_matching(pattern: str) -> set[str] | None:
    result = subprocess.run(
        ["git", "log", "--all", "--format=%H", "-G", pattern, "--"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        print("Unable to audit Git history for credential patterns.")
        return None
    return set(result.stdout.splitlines())


def commits_with_sensitive_paths() -> set[str] | None:
    result = subprocess.run(
        ["git", "log", "--all", "--format=%H", "--name-only", "--"],
        cwd=REPOSITORY_ROOT,
        capture_output=True,
        check=False,
        text=True,
    )
    if result.returncode != 0:
        print("Unable to audit Git history for credential file paths.")
        return None

    matches: set[str] = set()
    current_commit: str | None = None
    for line in result.stdout.splitlines():
        if re.fullmatch(r"[0-9a-f]{40,64}", line):
            current_commit = line
        elif current_commit and is_sensitive_path(line):
            matches.add(current_commit)
    return matches


def is_sensitive_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    # Example templates are not secret files and are intentionally tracked.
    if normalized.endswith((".env.example", ".env.docker.example")):
        return False
    return SENSITIVE_PATH.search(normalized) is not None


def main() -> int:
    findings: dict[str, set[str]] = {}
    for label, pattern in SECRET_PATTERNS.items():
        matches = commits_matching(pattern)
        if matches is None:
            return 2
        if matches:
            findings[label] = matches

    path_matches = commits_with_sensitive_paths()
    if path_matches is None:
        return 2
    if path_matches:
        findings["Sensitive credential file path"] = path_matches

    if findings:
        print("Credential-like material or sensitive files remain in Git history; values are suppressed:")
        for label, commits in findings.items():
            print(f"{label}:")
            for commit in sorted(commits):
                print(f"  {commit}")
        return 1

    print("No known credential patterns or sensitive credential file paths found on fetched Git refs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

