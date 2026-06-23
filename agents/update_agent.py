"""
Update Agent: takes the latest business analyst recommendation, asks Hermes to
generate a precise JSON edit plan, applies edits on a new git branch, runs tests,
then hands off to the Business Manager for review.
"""
import sys
import os
import json
import subprocess
import re
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from hermes_client import chat, is_available
from agent_memory import recall, reflect, record

PROJECT_ROOT = Path(__file__).parent.parent
RECS_DIR = Path(__file__).parent / "workspace" / "recommendations"
PENDING_DIR = Path(__file__).parent / "workspace" / "pending_changes"

EDIT_PROMPT = """\
You are a precise code editor for a Flask Python application. You will be given:
1. A recommendation describing a change to make
2. The current source file content

Your job: generate a JSON edit plan that makes EXACTLY the recommended change.

Output ONLY valid JSON — no explanation, no markdown fences:
{
  "edits": [
    {
      "file": "<relative file path from project root>",
      "description": "<one sentence: what this edit does>",
      "search": "<EXACT text to find — must exist verbatim in the file, include enough context to be unique>",
      "replace": "<replacement text>"
    }
  ]
}

Rules:
- Maximum 3 edits per recommendation
- Each search string MUST be unique in the file (include surrounding lines for context)
- Minimal change — only touch what's needed
- Preserve existing indentation exactly
- If a change is too complex or risky, output: {"edits": [], "skip_reason": "<explanation>"}"""


def _git(args, cwd=None):
    return subprocess.run(
        ["git"] + args,
        capture_output=True, text=True,
        cwd=cwd or str(PROJECT_ROOT)
    )


def get_latest_recommendation(skip_titles: list[str] | None = None) -> dict | None:
    files = sorted(RECS_DIR.glob("*.json"), reverse=True)
    if not files:
        return None
    data = json.loads(files[0].read_text())
    recs = data.get("recommendations", [])
    skip = set(skip_titles or [])
    for rec in sorted(recs, key=lambda r: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(r.get("priority", "LOW"), 1)):
        if rec.get("title", "") not in skip:
            return rec
    return None


def load_file_context(filepath: str) -> str:
    f = PROJECT_ROOT / filepath
    if not f.exists():
        return ""
    lines = f.read_text(errors="replace").splitlines()
    # Return first 500 lines — enough for Hermes context without overflowing
    return "\n".join(lines[:500])


def generate_edit_plan(rec: dict) -> dict:
    target_file = rec.get("file", "app.py")
    file_content = load_file_context(target_file)

    prompt = (
        f"Recommendation: {rec.get('title', '')}\n"
        f"Type: {rec.get('type', '')}\n"
        f"Description: {rec.get('description', '')}\n"
        f"Proposed change: {rec.get('proposed_change', '')}\n\n"
        f"Target file ({target_file}):\n```python\n{file_content}\n```"
    )
    memory = recall("update_agent")
    system = EDIT_PROMPT + (f"\n\n{memory}" if memory else "")
    raw = chat([
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ], timeout=180)

    try:
        cleaned = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {"edits": [], "skip_reason": f"Hermes JSON parse failed: {raw[:200]}"}


def apply_edits(edit_plan: dict) -> list[str]:
    """Apply edits to files. Returns list of files changed."""
    changed = []
    for edit in edit_plan.get("edits", []):
        f = PROJECT_ROOT / edit["file"]
        if not f.exists():
            print(f"  SKIP: {edit['file']} does not exist")
            continue
        content = f.read_text(errors="replace")
        if edit["search"] not in content:
            print(f"  SKIP: search string not found in {edit['file']}")
            print(f"    search: {edit['search'][:80]!r}")
            record("update_agent",
                   lesson=f"Search string not found in {edit['file']}. Include more surrounding context lines to make the search string uniquely locatable.",
                   lesson_type="mistake",
                   trigger=f"Edit for '{edit.get('description','')}' had unmatched search string",
                   confidence=0.85)
            continue
        count = content.count(edit["search"])
        if count > 1:
            print(f"  SKIP: search string appears {count}x in {edit['file']} — not unique enough")
            record("update_agent",
                   lesson=f"Search string was ambiguous in {edit['file']} ({count} matches). Always include the full function signature or surrounding 3+ lines to ensure uniqueness.",
                   lesson_type="mistake",
                   trigger=f"Edit search string matched {count} times",
                   confidence=0.9)
            continue
        f.write_text(content.replace(edit["search"], edit["replace"], 1))
        print(f"  EDITED: {edit['file']} — {edit['description']}")
        changed.append(edit["file"])
    return changed


def run_tests() -> tuple[str, int]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--tb=short", "-q", "--no-header", "-x"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    return result.stdout + result.stderr, result.returncode


def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", text.lower())[:40].strip("-")


def save_pending(rec: dict, branch: str, diff: str, test_output: str, test_ok: bool) -> tuple[Path, str]:
    import secrets
    PENDING_DIR.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    out = PENDING_DIR / f"{token}.json"
    out.write_text(json.dumps({
        "token": token,
        "status": "pending",
        "recommendation": rec,
        "branch": branch,
        "diff": diff,
        "test_output": test_output,
        "test_passed": test_ok,
        "created_at": datetime.utcnow().isoformat(),
    }, indent=2))
    return out, token


def main():
    if not is_available():
        print("ERROR: Ollama not running — start with: ollama serve")
        sys.exit(1)

    skipped: list[str] = []
    rec = None
    plan = None
    changed_files = []

    # Try up to 3 recommendations in priority order if Hermes skips or can't match
    for attempt in range(3):
        rec = get_latest_recommendation(skip_titles=skipped)
        if not rec:
            print("No actionable recommendations found. Run: python agents/run_agent.py analyze")
            sys.exit(0)

        print(f"\nImplementing (attempt {attempt + 1}): {rec.get('title')}")
        print(f"  File: {rec.get('file')}  |  Priority: {rec.get('priority')}")

        print("\nAsking Hermes to generate edit plan...")
        plan = generate_edit_plan(rec)

        if plan.get("skip_reason"):
            print(f"  Hermes skipped: {plan['skip_reason']} — trying next recommendation")
            skipped.append(rec.get("title", ""))
            continue

        changed_files = apply_edits(plan)
        if not changed_files:
            print("  No edits could be applied — trying next recommendation")
            skipped.append(rec.get("title", ""))
            continue

        break  # Got a workable edit
    else:
        print("All recommendations were skipped or unapplicable. Re-run analyze for fresh ideas.")
        sys.exit(0)

    # Check for uncommitted changes before branching
    status = _git(["status", "--porcelain"])
    stashed = False
    if status.stdout.strip():
        print("  Stashing uncommitted changes...")
        _git(["stash", "push", "-m", "pipeline-agent-stash"])
        stashed = True

    branch = f"pipeline/{datetime.utcnow().strftime('%Y-%m-%d')}-{slug(rec.get('title', 'change'))}"
    _git(["checkout", "-b", branch])
    print(f"  Branch: {branch}")

    try:
        _git(["add"] + changed_files)
        msg = f"Pipeline: {rec.get('title', 'automated change')}\n\nGenerated by Hermes update agent"
        _git(["commit", "-m", msg])

        # Get diff
        diff_result = _git(["diff", "main..HEAD"])
        diff = diff_result.stdout

        # Run tests
        print("\nRunning tests...")
        test_out, test_code = run_tests()
        test_ok = test_code == 0
        print(test_out[:1000])
        print(f"\nTests: {'PASSED' if test_ok else 'FAILED'}")

        # Learn from test outcomes
        if not test_ok:
            record("update_agent",
                   lesson=f"Changes for '{rec.get('title')}' caused test failures. Review the test output and ensure edits don't break existing contracts before committing.",
                   lesson_type="mistake",
                   trigger=f"Tests failed after implementing: {rec.get('title')}",
                   confidence=0.85)
        else:
            reflect("update_agent",
                    f"Implemented: {rec.get('title')}\nFiles changed: {changed_files}\nTests: PASSED",
                    "success")

        # Save pending change for business manager
        path, token = save_pending(rec, branch, diff, test_out, test_ok)
        print(f"\nPending change saved: {path.name}")

        # Hand off to business manager
        print("\nHanding off to Business Manager for review...")
        subprocess.run(
            [sys.executable, str(Path(__file__).parent / "business_manager.py"), token],
            cwd=str(PROJECT_ROOT),
        )

    finally:
        # Return to previous branch
        _git(["checkout", "-"])
        if stashed:
            _git(["stash", "pop"])


if __name__ == "__main__":
    main()
