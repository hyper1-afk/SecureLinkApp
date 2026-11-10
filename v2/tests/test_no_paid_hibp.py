"""Regression checks that SecureLink never re-enables paid HIBP lookups by accident."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_runtime_has_no_paid_hibp_credentials_or_endpoints():
    runtime_files = [
        REPO_ROOT / "app.py",
        REPO_ROOT / "config.py",
        REPO_ROOT / "features.py",
        REPO_ROOT / "dark_web_monitor.py",
        REPO_ROOT / ".env.docker.example",
    ]
    runtime = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)
    lowered = runtime.lower()

    assert "hibp_api_key" not in lowered
    assert "api/v3/breachedaccount" not in lowered
    assert "api/v3/pasteaccount" not in lowered
    assert "haveibeenpwned.com/api" not in lowered


def test_only_password_range_api_is_configured():
    monitor = (REPO_ROOT / "dark_web_monitor.py").read_text(encoding="utf-8")
    assert "https://api.pwnedpasswords.com" in monitor
    assert "/range/{prefix}" in monitor
