"""
Central entry point for all Hermes pipeline agents.

Usage:
  python agents/run_agent.py status           Check Ollama + hermes3
  python agents/run_agent.py fix-bugs         Scan core files for bugs
  python agents/run_agent.py fix-bugs <file>  Scan specific file(s)
  python agents/run_agent.py review           Review current git diff
  python agents/run_agent.py test             Run tests + Hermes analysis

  python agents/run_agent.py tickets          Check inbox + DB, draft replies
  python agents/run_agent.py analyze          Business analyst: find improvements
  python agents/run_agent.py implement        Update agent: implement top recommendation
  python agents/run_agent.py pipeline         Full cycle: analyze → implement → review
  python agents/run_agent.py manager [token]  Business manager review (list or review token)
"""
import sys
import os
import subprocess
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

AGENTS_DIR = Path(__file__).parent
PROJECT_ROOT = AGENTS_DIR.parent

TASKS = {
    # Core quality agents
    "status":    (None,                    "Check Ollama + hermes3 model status"),
    "fix-bugs":  ("bug_fixer.py",          "Scan source files for bugs and security issues"),
    "review":    ("code_reviewer.py",      "Review current git diff before pushing"),
    "test":      ("test_analyst.py",       "Run test suite and analyze failures"),
    # Pipeline agents
    "tickets":   ("ticket_handler.py",     "Check support inbox + DB, draft ticket replies"),
    "analyze":   ("business_analyst.py",   "Find improvement opportunities in the codebase"),
    "implement": ("update_agent.py",       "Implement top analyst recommendation + run tests"),
    "manager":   ("business_manager.py",   "Business manager review — list pending or review token"),
    "pipeline":  (None,                    "Full cycle: analyze → implement → tests → manager review"),
}

DEFAULT_BUG_TARGETS = [
    "app.py", "link_verifier.py", "domain_scanner.py",
    "database.py", "auth.py", "scan_scheduler.py",
]


def _run(script: str, extra_args: list[str]) -> int:
    result = subprocess.run(
        [sys.executable, str(AGENTS_DIR / script)] + extra_args,
        cwd=str(PROJECT_ROOT),
    )
    return result.returncode


def cmd_status() -> int:
    from hermes_client import is_available, OLLAMA_URL, DEFAULT_MODEL
    import urllib.request, urllib.error
    print("Checking Ollama...")
    try:
        urllib.request.urlopen(f"{OLLAMA_URL}/api/tags", timeout=3)
        print(f"  Ollama:  running at {OLLAMA_URL}")
    except Exception:
        print(f"  Ollama:  NOT running  (start: ollama serve)")
        return 1
    if is_available():
        print(f"  Model:   {DEFAULT_MODEL} ready")
        return 0
    print(f"  Model:   {DEFAULT_MODEL} not found  (pull: ollama pull {DEFAULT_MODEL})")
    return 1


def cmd_pipeline() -> int:
    """Run the full autonomous pipeline: analyze → implement → (manager sends email)."""
    print("=" * 60)
    print("SecureLink Autonomous Pipeline")
    print("=" * 60)

    print("\n[1/2] Business Analyst: scanning for improvements...")
    rc = _run("business_analyst.py", [])
    if rc != 0:
        print("Analyst failed. Aborting pipeline.")
        return rc

    print("\n[2/2] Update Agent: implementing top recommendation...")
    rc = _run("update_agent.py", [])
    # update_agent automatically calls business_manager at the end
    return rc


def main():
    if len(sys.argv) < 2 or sys.argv[1] not in TASKS:
        print("Usage: python agents/run_agent.py <task> [args]\n")
        print("Tasks:")
        for name, (_, desc) in TASKS.items():
            print(f"  {name:<14} {desc}")
        print("\nExamples:")
        print("  python agents/run_agent.py tickets")
        print("  python agents/run_agent.py analyze")
        print("  python agents/run_agent.py implement")
        print("  python agents/run_agent.py pipeline")
        sys.exit(1)

    task = sys.argv[1]
    extra_args = sys.argv[2:]

    if task == "status":
        sys.exit(cmd_status())

    if task == "pipeline":
        sys.exit(cmd_pipeline())

    if task == "fix-bugs" and not extra_args:
        extra_args = [f for f in DEFAULT_BUG_TARGETS if (PROJECT_ROOT / f).exists()]

    script, _ = TASKS[task]
    sys.exit(_run(script, extra_args))


if __name__ == "__main__":
    main()
