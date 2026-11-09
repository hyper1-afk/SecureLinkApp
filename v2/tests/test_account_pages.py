from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from apps.api import emailer, main
from apps.api.config import Settings


def test_account_pages_have_sensitive_page_headers_and_assets():
    client = TestClient(main.app)
    for path in ("/", "/verify-email", "/reset-password"):
        response = client.get(path)
        assert response.status_code == 200
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["referrer-policy"] == "no-referrer"
        assert "default-src 'none'" in response.headers["content-security-policy"]

    assert client.get("/assets/verify-email.js").status_code == 200
    assert client.get("/assets/reset-password.js").status_code == 200


def test_account_action_email_keeps_token_in_url_fragment(monkeypatch):
    settings = Settings(
        app_public_url="https://staging.example.test",
        smtp_host="mail.example.test",
        smtp_from_email="no-reply@example.test",
        email_outbox_encryption_key=Fernet.generate_key().decode("ascii"),
    )
    monkeypatch.setattr(emailer, "get_settings", lambda: settings)

    class FakeSMTP:
        message = None

        def __init__(self, *_args, **_kwargs):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def starttls(self, **_kwargs):
            return None

        def send_message(self, message):
            self.message = message

    smtp = FakeSMTP()
    monkeypatch.setattr(emailer.smtplib, "SMTP", lambda *_args, **_kwargs: smtp)
    emailer.send_action_email("verify_email", "person@example.test", "opaque-token")

    body = smtp.message.get_content()
    assert "https://staging.example.test/verify-email#token=opaque-token" in body
    assert "/verify-email?token=" not in body
