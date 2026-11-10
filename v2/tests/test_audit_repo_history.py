import re

from scripts.audit_repo_history import SECRET_PATTERNS, is_sensitive_path


def test_history_audit_recognizes_common_credential_formats():
    examples = {
        "Google API key": "AIza" + "A" * 35,
        "AWS access key ID": "AKIA" + "A" * 16,
        "GitHub access token": "ghp_" + "a" * 24,
        "Slack token": "xoxb-" + "a" * 24,
        "Stripe secret key": "sk_live_" + "a" * 16,
        "Google OAuth client secret": "GOCSPX-" + "a" * 24,
        "SendGrid API key": "SG." + "a" * 22 + "." + "b" * 43,
        "NPM access token": "npm_" + "a" * 36,
        "Private key material": "-----BEGIN " + "PRIVATE KEY-----",
    }

    for label, example in examples.items():
        assert re.search(SECRET_PATTERNS[label], example), label


def test_history_audit_flags_sensitive_files_but_allows_env_templates():
    assert is_sensitive_path("v2/.env.production")
    assert is_sensitive_path("keys/service.pem")
    assert is_sensitive_path("keys/id_ed25519")
    assert not is_sensitive_path(".env.example")
    assert not is_sensitive_path(".env.docker.example")

