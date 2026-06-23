"""Run the project's test suite and use Hermes to diagnose failures."""
import sys
import os
import subprocess
from pathlib import Path

sys.path.insert(0, os.path.dirname(__file__))
from hermes_client import chat, is_available

SYSTEM_PROMPT = """\
You are a Python debugging expert for a Flask security application (SecureLink). \
Given pytest output, identify the root cause of every failure and provide \
actionable fix instructions.

For each failing test output exactly:

FAILING_TEST: <test name>
ROOT_CAUSE: <clear explanation — is it a test issue or production code issue?>
AFFECTED_FILE: <file and function/line to fix>
FIX: <specific, concrete steps to resolve it>

If all tests passed, output: ALL_TESTS_PASSED"""

PROJECT_ROOT = Path(__file__).parent.parent


def run_tests() -> tuple[str, int]:
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--tb=short", "-q", "--no-header"],
        capture_output=True,
        text=True,
        cwd=str(PROJECT_ROOT),
    )
    return result.stdout + result.stderr, result.returncode


def analyze(output: str) -> str:
    if len(output) > 6000:
        output = output[:6000] + "\n[... output truncated ...]"
    return chat([
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": output},
    ])


def main():
    print("Running test suite...")
    output, code = run_tests()
    print(output)

    if code == 0:
        print("All tests passed.")
        sys.exit(0)

    if not is_available():
        print("Tests failed. Ollama is not running — cannot run Hermes analysis.")
        print("  Start with: ollama serve && ollama pull hermes3")
        sys.exit(1)

    print("\n" + "=" * 60)
    print("Hermes Test Failure Analysis")
    print("=" * 60)
    analysis = analyze(output)
    print(analysis)
    sys.exit(1)


if __name__ == "__main__":
    main()
