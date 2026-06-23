"""Hermes-powered bug detection for Python/JS source files."""
import sys
import os
import argparse
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from hermes_client import chat, is_available
from agent_memory import recall, reflect

SYSTEM_PROMPT = """\
You are an expert Python and JavaScript security-aware bug detector for a Flask \
web application. Analyze the provided source file and identify:

1. Logic errors and bugs
2. Security vulnerabilities (SQL injection, XSS, path traversal, unvalidated input)
3. Authentication/authorization flaws
4. Unhandled edge cases that could cause 500 errors
5. Race conditions or resource leaks

For every issue found, output exactly this block (no markdown fences):

ISSUE: <brief title>
SEVERITY: CRITICAL|HIGH|MEDIUM|LOW
LINE: <line number or "unknown">
DESCRIPTION: <clear explanation of the problem>
FIX: <concrete, specific fix>

If no issues are found, output exactly: NO_ISSUES_FOUND"""


def analyze_file(path: str) -> str:
    code = Path(path).read_text(encoding="utf-8", errors="replace")
    # Trim very large files to the first 600 lines to stay within context
    lines = code.splitlines()
    if len(lines) > 600:
        code = "\n".join(lines[:600]) + f"\n\n[... {len(lines)-600} lines omitted ...]"
    memory = recall("bug_scanner")
    system = SYSTEM_PROMPT + (f"\n\n{memory}" if memory else "")
    return chat([
        {"role": "system", "content": system},
        {"role": "user", "content": f"File: {path}\n\n```\n{code}\n```"},
    ])


def main():
    parser = argparse.ArgumentParser(description="Hermes bug detector")
    parser.add_argument("files", nargs="+", help="Source files to analyze")
    args = parser.parse_args()

    if not is_available():
        print("ERROR: Ollama is not running or hermes3 is not pulled.")
        print("  Start Ollama:  ollama serve")
        print("  Pull model:    ollama pull hermes3")
        sys.exit(1)

    has_issues = False
    all_output = []
    for f in args.files:
        if not Path(f).exists():
            print(f"SKIP: {f} not found")
            continue
        print(f"\n{'='*60}")
        print(f"Analyzing: {f}")
        print("=" * 60)
        result = analyze_file(f)
        print(result)
        all_output.append(result)
        if "NO_ISSUES_FOUND" not in result:
            has_issues = True

    outcome = "found_issues" if has_issues else "success"
    reflect("bug_scanner", "\n".join(all_output), outcome)
    sys.exit(0)  # Exit 0 always — finding bugs is a successful scan, not an agent error


if __name__ == "__main__":
    main()
