import base64

import pytest
from pydantic import ValidationError

from apps.api.config import Settings


def deployment_settings(**overrides):
    values = {
        "app_env": "staging",
        "app_public_url": "https://staging.example.test",
        "database_url": "postgresql+psycopg://securelink:unique@postgres.internal:5432/securelink",
        "redis_url": "rediss://redis.internal:6379/0",
        "app_secret_key": "s" * 48,
        "email_outbox_encryption_key": base64.urlsafe_b64encode(b"e" * 32).decode(),
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_username": "staging-user",
        "smtp_password": "staging-password",
        "smtp_from_email": "staging@example.test",
        "smtp_starttls": True,
    }
    values.update(overrides)
    return values


def test_deployment_settings_accept_complete_staging_configuration():
    settings = Settings(**deployment_settings())

    assert settings.app_env == "staging"


@pytest.mark.parametrize(
    ("override", "message"),
    [
        ({"app_public_url": "http://staging.example.test"}, "APP_PUBLIC_URL must use HTTPS"),
        ({"app_secret_key": "short"}, "APP_SECRET_KEY must contain at least 32 bytes"),
        (
            {
                "database_url": (
                    "postgresql+psycopg://securelink:change-this-local-password"
                    "@db:5432/securelink"
                )
            },
            "DATABASE_URL must not use the local example credential",
        ),
        (
            {"database_url": "postgresql+psycopg://securelink:unique@localhost:5432/securelink"},
            "DATABASE_URL must point to the deployment database",
        ),
        (
            {"redis_url": "redis://user:pass@localhost:6379/0"},
            "REDIS_URL must point to the deployment Redis service",
        ),
        ({"email_outbox_encryption_key": None}, "EMAIL_OUTBOX_ENCRYPTION_KEY must be set"),
        (
            {"email_outbox_encryption_key": "not-a-fernet-key"},
            "EMAIL_OUTBOX_ENCRYPTION_KEY must be a valid Fernet key",
        ),
        ({"smtp_starttls": False}, "SMTP_STARTTLS must be enabled"),
        ({"smtp_password": None}, "SMTP_PASSWORD is required when SMTP_USERNAME is set"),
    ],
)
def test_deployment_settings_reject_insecure_or_incomplete_values(override, message):
    with pytest.raises(ValidationError, match=message):
        Settings(**deployment_settings(**override))


def test_development_settings_keep_local_defaults():
    settings = Settings(app_env="development")

    assert settings.database_url.endswith("@localhost:5432/securelink")
