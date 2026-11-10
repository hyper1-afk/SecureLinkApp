"""Regression checks that SecureLink never re-enables paid HIBP lookups by accident."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_runtime_has_no_paid_hibp_credentials_or_endpoints():
    runtime_files = [
        REPO_ROOT / "app.py",
        REPO_ROOT / "config.py",
        REPO_ROOT / "features.py",
        REPO_ROOT / "dark_web_monitor.py",
        REPO_ROOT / "domain_scanner.py",
        REPO_ROOT / "vercel.json",
        REPO_ROOT / ".env.example",
        REPO_ROOT / ".env.docker.example",
    ]
    runtime = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)
    lowered = runtime.lower()

    assert "hibp_api_key" not in lowered
    assert "api/v3/breachedaccount" not in lowered
    assert "api/v3/pasteaccount" not in lowered
    assert "api/v3/breaches" not in lowered
    assert "haveibeenpwned.com/api" not in lowered


def test_only_password_range_api_is_configured():
    monitor = (REPO_ROOT / "dark_web_monitor.py").read_text(encoding="utf-8")
    assert "https://api.pwnedpasswords.com" in monitor
    assert "/range/{prefix.upper()}" in monitor


def test_breach_checker_does_not_collect_email_for_disabled_lookup():
    page = (REPO_ROOT / "templates" / "breach_checker.html").read_text(encoding="utf-8").lower()
    assert 'id="emailinput"' not in page
    assert "function checkemail" not in page
    assert "/api/breach/email" not in page
    assert 'id="passwordinput"' in page


def test_workspace_does_not_offer_disabled_email_breach_lookup():
    page = (REPO_ROOT / "templates" / "workspace.html").read_text(encoding="utf-8").lower()
    assert "check against 700+ breach databases" not in page
    assert "async function breachcheckapi" not in page
    assert "'/api/public/breach-check'" not in page


def test_password_checker_hashes_in_browser_and_discloses_prefix_transfer():
    page = (REPO_ROOT / "templates" / "breach_checker.html").read_text(encoding="utf-8").lower()
    assert "your browser hashes the password locally" in page
    assert "complete password and hash stay in your browser" in page
    assert "we never send your actual password" not in page


def test_password_range_api_accepts_only_hash_prefixes():
    api = (REPO_ROOT / "app.py").read_text(encoding="utf-8")
    start = api.index("def check_password_hash_range():")
    end = api.index("# ============== Subscription Routes ==============", start)
    route = api[start:end]
    assert "data.get('prefix')" in route
    assert "[A-Fa-f0-9]{5}" in route
    assert "data.get('password')" not in route

    monitor = (REPO_ROOT / "dark_web_monitor.py").read_text(encoding="utf-8")
    assert '"Add-Padding": "true"' in monitor
    assert "def check_password_pwned(" not in monitor


def test_password_checker_client_sends_only_prefix():
    client = (REPO_ROOT / "static" / "js" / "password-exposure-check.mjs").read_text(encoding="utf-8")
    assert "JSON.stringify({ prefix })" in client
    assert "credentials: \"omit\"" in client
    assert "JSON.stringify({ password })" not in client
