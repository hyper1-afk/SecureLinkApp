from functools import lru_cache
from urllib.parse import urlsplit

from cryptography.fernet import Fernet
from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy.engine import make_url


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_env: str = "development"
    app_public_url: str = "http://localhost:3000"
    database_url: str = "postgresql+psycopg://securelink:change-this-local-password@localhost:5432/securelink"
    redis_url: str = "redis://redis:6379/0"
    app_secret_key: str | None = None
    smtp_host: str | None = None
    smtp_port: int = 587
    smtp_username: str | None = None
    smtp_password: str | None = None
    smtp_from_email: str | None = None
    smtp_starttls: bool = True
    email_outbox_encryption_key: str | None = None
    trusted_proxy_cidrs: str = ""

    @model_validator(mode="after")
    def validate_deployment_settings(self) -> "Settings":
        if self.app_env not in {"staging", "production"}:
            return self

        problems: list[str] = []
        if not self.app_public_url.startswith("https://"):
            problems.append("APP_PUBLIC_URL must use HTTPS")
        if not self.app_secret_key or len(self.app_secret_key.encode("utf-8")) < 32:
            problems.append("APP_SECRET_KEY must contain at least 32 bytes")
        if self.app_secret_key and "replace-with" in self.app_secret_key:
            problems.append("APP_SECRET_KEY must not use the example placeholder")
        database = make_url(self.database_url)
        if "change-this-local-password" in (database.password or ""):
            problems.append("DATABASE_URL must not use the local example credential")
        if database.host in {"localhost", "127.0.0.1", "::1"}:
            problems.append("DATABASE_URL must point to the deployment database")
        redis_host = urlsplit(self.redis_url).hostname
        if redis_host in {"localhost", "127.0.0.1", "::1"}:
            problems.append("REDIS_URL must point to the deployment Redis service")
        if not self.email_outbox_encryption_key or "replace-with" in self.email_outbox_encryption_key:
            problems.append("EMAIL_OUTBOX_ENCRYPTION_KEY must be set to a unique secret")
        else:
            try:
                Fernet(self.email_outbox_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError, TypeError):
                problems.append("EMAIL_OUTBOX_ENCRYPTION_KEY must be a valid Fernet key")
        if not self.smtp_starttls:
            problems.append("SMTP_STARTTLS must be enabled")
        if not all((self.smtp_host, self.smtp_from_email)):
            problems.append("SMTP host and sender must be configured")
        if self.smtp_username and not self.smtp_password:
            problems.append("SMTP_PASSWORD is required when SMTP_USERNAME is set")
        if problems:
            raise ValueError("Invalid staging/production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
