from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


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


@lru_cache
def get_settings() -> Settings:
    return Settings()
