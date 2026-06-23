"""Hermes-powered review of git diffs before pushing."""
import sys
import os
import subprocess

sys.path.insert(0, os.path.dirname(__file__))
from hermes_client import chat, is_available
from agent_memory import recall, reflect

SYSTEM_PROMPT = """\
You are a senior security-focused code reviewer for SecureLink, a Flask URL \
threat-scanning platform. Review the provided git diff and check for:

1. Security vulnerabilities — auth bypass, injection, exposed secrets, broken JWT
2. Bugs that would break existing functionality or API contracts
3. Missing input validation at /api/* boundaries
4. Regressions in URL scanning, domain health checks, or breach detection
5. Hardcoded credentials or API keys accidentally committed

Output format (no markdown fences):

VERDICT: APPROVE|REQUEST_CHANGES|BLOCK

For each issue (omit section if none):
ISSUE: <title>
SEVERITY: CRITICAL|HIGH|MEDIUM|LOW
FILE: <filename>
LINE: <line or "unknown">
DESCRIPTION: <explanation>
SUGGESTION: <how to fix>

BLOCK = must fix before pushing (CRITICAL security issue or data loss risk)
REQUEST_CHANGES = should fix but not mandatory
APPROVE = no significant issues"""


def get_diff() -> str:
    # Prefer diff of what would actually be pushed (staged + committed ahead of remote)
    for cmd in (
        ["git", "diff", "origin/HEAD...HEAD"],
        ["git", "diff", "--cached"],
        ["git", "diff", "HEAD"],
    ):
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.stdout.strip():
            return result.stdout
    return ""


def review_diff(diff: str) -> str:
    if not diff.strip():
        return "VERDICT: APPROVE\nNo diff detected — nothing to review."
    if len(diff) > 8000:
        diff = diff[:8000] + "\n\n[... diff truncated for length ...]"
    memory = recall("code_reviewer")
    system = SYSTEM_PROMPT + (f"\n\n{memory}" if memory else "")
    return chat([
        {"role": "system", "content": system},
        {"role": "user", "content": f"```diff\n{diff}\n```"},
    ])


def main():
    if not is_available():
        print("WARNING: Ollama not running — skipping Hermes review.")
        print("  Start with: ollama serve")
        sys.exit(0)  # Non-blocking: don't prevent push if Ollama is down

    diff = get_diff()
    print("\n" + "=" * 60)
    print("Hermes Code Review")
    print("=" * 60)
    result = review_diff(diff)
    print(result)
    print("=" * 60)

    outcome = "error" if "BLOCK" in result else ("warning" if "REQUEST_CHANGES" in result else "success")
    reflect("code_reviewer", result, outcome)

    if "VERDICT: BLOCK" in result:
        print("\nPush BLOCKED by Hermes — fix CRITICAL issues before pushing.")
        sys.exit(1)

    if "VERDICT: REQUEST_CHANGES" in result:
        if sys.stdin.isatty():
            # Interactive terminal — ask the developer
            print("\nHermes requests changes. Push anyway? [y/N]: ", end="", flush=True)
            try:
                ans = input().strip().lower()
            except EOFError:
                ans = "n"
            sys.exit(0 if ans == "y" else 1)
        else:
            # Non-interactive (scheduler / CI subprocess) — log and continue
            print("\nHermes requests changes (non-interactive: proceeding, review findings above).")
            sys.exit(0)

    sys.exit(0)


if __name__ == "__main__":
    main()
