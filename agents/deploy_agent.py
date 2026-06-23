"""
Deploy agent: merges an approved pipeline branch into main and pushes to production.
Called by the Flask /api/pipeline/review endpoint after admin approves.
"""
import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent
PENDING_DIR = Path(__file__).parent / "workspace" / "pending_changes"


def _git(args, cwd=None):
    result = subprocess.run(
        ["git"] + args,
        capture_output=True, text=True,
        cwd=cwd or str(PROJECT_ROOT),
    )
    return result


def load_pending(token: str) -> dict:
    f = PENDING_DIR / f"{token}.json"
    if not f.exists():
        raise FileNotFoundError(f"No pending change for token: {token}")
    return json.loads(f.read_text())


def update_status(token: str, update: dict):
    f = PENDING_DIR / f"{token}.json"
    data = json.loads(f.read_text())
    data.update(update)
    f.write_text(json.dumps(data, indent=2))


def deploy(token: str) -> tuple[bool, str]:
    """Merge approved branch into main and push. Returns (success, message)."""
    change = load_pending(token)
    branch = change.get("branch")

    if change.get("status") == "deployed":
        return False, "Already deployed."
    if change.get("status") == "denied":
        return False, "Change was denied — cannot deploy."
    if change.get("status") != "approved":
        return False, f"Change is not approved (status: {change.get('status')})."

    print(f"Deploying branch: {branch}")

    # Ensure we're on main
    r = _git(["checkout", "main"])
    if r.returncode != 0:
        return False, f"Failed to checkout main: {r.stderr}"

    # Pull latest main
    _git(["pull", "origin", "main"])

    # Merge the pipeline branch (no-ff so merge commit is visible)
    r = _git(["merge", "--no-ff", branch, "-m",
              f"Deploy: {change['recommendation'].get('title','pipeline change')} [approved by admin]"])
    if r.returncode != 0:
        return False, f"Merge failed:\n{r.stderr}"

    # Push to origin (triggers Vercel/DigitalOcean auto-deploy)
    r = _git(["push", "origin", "main"])
    if r.returncode != 0:
        return False, f"Push failed:\n{r.stderr}"

    # Clean up the pipeline branch
    _git(["branch", "-d", branch])
    try:
        _git(["push", "origin", "--delete", branch])
    except Exception:
        pass

    update_status(token, {
        "status": "deployed",
        "deployed_at": datetime.utcnow().isoformat(),
    })
    return True, f"Branch '{branch}' merged to main and pushed. Auto-deploy triggered."


def deny(token: str) -> tuple[bool, str]:
    """Mark change as denied and delete the branch."""
    change = load_pending(token)
    branch = change.get("branch")

    if change.get("status") in ("deployed", "denied"):
        return False, f"Already {change['status']}."

    # Delete local branch if it exists
    _git(["branch", "-D", branch])
    try:
        _git(["push", "origin", "--delete", branch])
    except Exception:
        pass

    update_status(token, {
        "status": "denied",
        "denied_at": datetime.utcnow().isoformat(),
    })
    return True, f"Change denied. Branch '{branch}' deleted."


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python agents/deploy_agent.py <approve|deny> <token>")
        sys.exit(1)
    action, tok = sys.argv[1], sys.argv[2]
    if action == "approve":
        ok, msg = deploy(tok)
    elif action == "deny":
        ok, msg = deny(tok)
    else:
        print(f"Unknown action: {action}")
        sys.exit(1)
    print(msg)
    sys.exit(0 if ok else 1)
