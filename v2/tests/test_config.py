import base64

import pytest
from pydantic import ValidationError

from apps.api.config import Settings


def deployment_settings(**overrides):
    values = {
        "app_env": "staging",
        "app_public_url": "https://staging.example.test",
        "database_url": (
            "postgresql+psycopg://securelink:unique@postgres.internal:5432/securelink"
            "?sslmode=verify-full&sslrootcert=system"
        ),
        "redis_url": "rediss://:unique@redis.internal:6379/0",
        "app_secret_key": "s" * 48,
        "email_outbox_encryption_key": base64.urlsafe_b64encode(b"e" * 32).decode(),
        "mfa_encryption_key": base64.urlsafe_b64encode(b"m" * 32).decode(),
        "smtp_host": "smtp.example.test",
        "smtp_port": 587,
        "smtp_username": "staging-user",
        "smtp_password": "staging-password",
        "smtp_from_email": "staging@example.test",
        "smtp_starttls": True,
        "domain_dns_resolvers": "1.1.1.1,1.0.0.1",
        "extension_redirect_uris": "https://dpegeipjmofhdikcbniodhohpckoeole.chromiumapp.org/",
    }
    values.update(overrides)
    return values


def test_deployment_settings_accept_complete_staging_configuration():
    settings = Settings(**deployment_settings())

    assert settings.app_env == "staging"


def test_deployment_settings_accepts_the_exact_staging_extension_callback():
    callback = "https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/"

    settings = Settings(**deployment_settings(extension_redirect_uris=callback))

    assert settings.extension_redirect_uris == callback


@pytest.mark.parametrize(
    ("override", "message"),
    [
        (
            {"app_public_url": "http://staging.example.test"},
            "APP_PUBLIC_URL must be an HTTPS origin",
        ),
        (
            {"app_public_url": "https://staging.example.test/dashboard"},
            "APP_PUBLIC_URL must be an HTTPS origin",
        ),
        (
            {"app_public_url": "https://staging.example.test:8443"},
            "APP_PUBLIC_URL must be an HTTPS origin",
        ),
        (
            {"app_public_url": "https://127.0.0.1"},
            "APP_PUBLIC_URL must be an HTTPS origin",
        ),
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
            {
                "database_url": (
                    "postgresql+psycopg://securelink:unique@localhost:5432/securelink"
                    "?sslmode=verify-full&sslrootcert=system"
                )
            },
            "DATABASE_URL must point to the deployment database",
        ),
        (
            {"redis_url": "rediss://user:pass@localhost:6379/0"},
            "REDIS_URL must point to the deployment Redis service",
        ),
        (
            {"redis_url": "redis://redis.internal:6379/0"},
            "REDIS_URL must use TLS",
        ),
        (
            {"redis_url": "rediss://redis.internal:6379/0"},
            "REDIS_URL must include a Redis password",
        ),
        (
            {"redis_url": "rediss://redis.internal:6379/0?ssl_cert_reqs=none"},
            "REDIS_URL must verify the TLS certificate and hostname",
        ),
        (
            {"redis_url": "rediss://redis.internal:6379/0?ssl_check_hostname=false"},
            "REDIS_URL must verify the TLS certificate and hostname",
        ),
        (
            {"database_url": "sqlite:///./not-production.db"},
            "DATABASE_URL must use PostgreSQL",
        ),
        (
            {
                "database_url": (
                    "postgresql+psycopg://@postgres.internal:5432/securelink"
                    "?sslmode=verify-full&sslrootcert=system"
                )
            },
            "DATABASE_URL must include a database username and password",
        ),
        (
            {"trusted_proxy_cidrs": "not-a-cidr"},
            "TRUSTED_PROXY_CIDRS must contain valid IP networks",
        ),
        (
            {"trusted_proxy_cidrs": "0.0.0.0/0"},
            "TRUSTED_PROXY_CIDRS must not trust a default route",
        ),
        (
            {
                "database_url": (
                    "postgresql+psycopg://securelink:unique@postgres.internal:5432/securelink"
                )
            },
            "DATABASE_URL must verify the PostgreSQL certificate and hostname",
        ),
        (
            {
                "database_url": (
                    "postgresql+psycopg://securelink:unique@postgres.internal:5432/securelink"
                    "?sslmode=require"
                )
            },
            "DATABASE_URL must verify the PostgreSQL certificate and hostname",
        ),
        (
            {
                "database_url": (
                    "postgresql+psycopg://securelink:unique@postgres.internal:5432/securelink"
                    "?sslmode=verify-full"
                )
            },
            "DATABASE_URL must verify the PostgreSQL certificate and hostname",
        ),
        ({"email_outbox_encryption_key": None}, "EMAIL_OUTBOX_ENCRYPTION_KEY must be set"),
        ({"mfa_encryption_key": None}, "MFA_ENCRYPTION_KEY must be set"),
        ({"mfa_encryption_key": "invalid-key"}, "MFA_ENCRYPTION_KEY must be a valid Fernet key"),
        (
            {"mfa_encryption_key": base64.urlsafe_b64encode(b"e" * 32).decode()},
            "MFA_ENCRYPTION_KEY must be different from EMAIL_OUTBOX_ENCRYPTION_KEY",
        ),
        (
            {"email_outbox_encryption_key": "not-a-fernet-key"},
            "EMAIL_OUTBOX_ENCRYPTION_KEY must be a valid Fernet key",
        ),
        ({"smtp_starttls": False}, "SMTP_STARTTLS must be enabled"),
        ({"smtp_password": None}, "SMTP_PASSWORD is required when SMTP_USERNAME is set"),
        (
            {"extension_redirect_uris": "https://attacker.example.test/callback"},
            "EXTENSION_REDIRECT_URIS contains an invalid Chrome extension redirect URI",
        ),
    ],
)
def test_deployment_settings_reject_insecure_or_incomplete_values(override, message):
    with pytest.raises(ValidationError, match=message):
        Settings(**deployment_settings(**override))


def test_development_settings_keep_local_defaults():
    settings = Settings(app_env="development")

    assert settings.database_url.endswith("@localhost:5432/securelink")


@pytest.mark.parametrize(
    "resolvers",
    ["", "resolver.example.test", "1.1.1.1,not-an-ip", "127.0.0.1", "0.0.0.0", "224.0.0.1"],
)
def test_deployment_requires_numeric_dns_resolvers(resolvers):
    with pytest.raises(ValidationError, match="DOMAIN_DNS_RESOLVERS"):
        Settings(**deployment_settings(domain_dns_resolvers=resolvers))
