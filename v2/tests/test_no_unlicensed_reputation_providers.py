"""Keep unreviewed URL reputation services out of the commercial runtime."""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def test_runtime_has_no_unapproved_url_reputation_integrations():
    runtime_files = [
        REPO_ROOT / "config.py",
        REPO_ROOT / "link_verifier.py",
        REPO_ROOT / ".env.example",
        REPO_ROOT / ".env.docker.example",
        REPO_ROOT / "docker-compose.yml",
    ]
    runtime = "\n".join(path.read_text(encoding="utf-8") for path in runtime_files)
    lowered = runtime.lower()

    unapproved_markers = (
        "google_safe_browsing_api_key",
        "safebrowsing.googleapis.com",
        "virustotal_api_key",
        "virustotal.com/api",
        "abuseipdb_api_key",
        "api.abuseipdb.com",
        "urlhaus.abuse.ch/api",
    )
    for marker in unapproved_markers:
        assert marker not in lowered
