import ipaddress
import re
from functools import lru_cache
from urllib.parse import parse_qs, urlsplit

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
    mfa_encryption_key: str | None = None
    trusted_proxy_cidrs: str = ""
    extension_redirect_uris: str = ""
    domain_dns_resolvers: str = ""

    @model_validator(mode="after")
    def validate_deployment_settings(self) -> "Settings":
        if self.app_env not in {"staging", "production"}:
            return self

        problems: list[str] = []
        public_url = urlsplit(self.app_public_url)
        try:
            public_port = public_url.port
        except ValueError:
            public_port = -1
        try:
            public_address = ipaddress.ip_address(public_url.hostname or "")
        except ValueError:
            public_address = None
        if (
            public_url.scheme != "https"
            or not public_url.hostname
            or public_url.hostname.casefold() == "localhost"
            or (public_address is not None and not public_address.is_global)
            or public_url.username
            or public_url.password
            or public_url.path not in {"", "/"}
            or public_port not in {None, 443}
            or public_url.query
            or public_url.fragment
        ):
            problems.append("APP_PUBLIC_URL must be an HTTPS origin without credentials or extra path")
        if not self.app_secret_key or len(self.app_secret_key.encode("utf-8")) < 32:
            problems.append("APP_SECRET_KEY must contain at least 32 bytes")
        if self.app_secret_key and "replace-with" in self.app_secret_key:
            problems.append("APP_SECRET_KEY must not use the example placeholder")
        database = make_url(self.database_url)
        if not database.drivername.startswith("postgresql"):
            problems.append("DATABASE_URL must use PostgreSQL")
        if "change-this-local-password" in (database.password or ""):
            problems.append("DATABASE_URL must not use the local example credential")
        if not database.host or database.host in {"localhost", "127.0.0.1", "::1"}:
            problems.append("DATABASE_URL must point to the deployment database")
        if not database.username or not database.password:
            problems.append("DATABASE_URL must include a database username and password")
        if database.query.get("sslmode") != "verify-full" or not database.query.get("sslrootcert"):
            problems.append(
                "DATABASE_URL must verify the PostgreSQL certificate and hostname with a trusted CA"
            )
        redis = urlsplit(self.redis_url)
        if redis.scheme != "rediss":
            problems.append("REDIS_URL must use TLS")
        if not redis.hostname or redis.hostname in {"localhost", "127.0.0.1", "::1"}:
            problems.append("REDIS_URL must point to the deployment Redis service")
        if not redis.password:
            problems.append("REDIS_URL must include a Redis password")
        redis_options = parse_qs(redis.query, keep_blank_values=True)
        cert_reqs = [value.casefold() for value in redis_options.get("ssl_cert_reqs", [])]
        hostname_checks = [
            value.casefold() for value in redis_options.get("ssl_check_hostname", [])
        ]
        if any(value != "required" for value in cert_reqs) or any(
            value not in {"1", "true", "yes", "on"} for value in hostname_checks
        ):
            problems.append("REDIS_URL must verify the TLS certificate and hostname")
        if not self.email_outbox_encryption_key or "replace-with" in self.email_outbox_encryption_key:
            problems.append("EMAIL_OUTBOX_ENCRYPTION_KEY must be set to a unique secret")
        else:
            try:
                Fernet(self.email_outbox_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError, TypeError):
                problems.append("EMAIL_OUTBOX_ENCRYPTION_KEY must be a valid Fernet key")
        if not self.mfa_encryption_key or "replace-with" in self.mfa_encryption_key:
            problems.append("MFA_ENCRYPTION_KEY must be set to a unique secret")
        else:
            try:
                Fernet(self.mfa_encryption_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError, TypeError):
                problems.append("MFA_ENCRYPTION_KEY must be a valid Fernet key")
            if self.mfa_encryption_key == self.email_outbox_encryption_key:
                problems.append("MFA_ENCRYPTION_KEY must be different from EMAIL_OUTBOX_ENCRYPTION_KEY")
        if not self.smtp_starttls:
            problems.append("SMTP_STARTTLS must be enabled")
        resolvers = [item.strip() for item in self.domain_dns_resolvers.split(",") if item.strip()]
        if not resolvers:
            problems.append("DOMAIN_DNS_RESOLVERS must list approved recursive resolver IPs")
        else:
            try:
                for resolver in resolvers:
                    address = ipaddress.ip_address(resolver)
                    if address.is_unspecified or address.is_loopback or address.is_multicast:
                        raise ValueError("DNS resolver address is not usable")
            except ValueError:
                problems.append("DOMAIN_DNS_RESOLVERS must contain usable numeric unicast IP addresses")
        proxy_cidrs = [item.strip() for item in self.trusted_proxy_cidrs.split(",") if item.strip()]
        try:
            networks = [ipaddress.ip_network(value, strict=False) for value in proxy_cidrs]
        except ValueError:
            problems.append("TRUSTED_PROXY_CIDRS must contain valid IP networks")
        else:
            if any(network.prefixlen == 0 for network in networks):
                problems.append("TRUSTED_PROXY_CIDRS must not trust a default route")
        if not all((self.smtp_host, self.smtp_from_email)):
            problems.append("SMTP host and sender must be configured")
        if self.smtp_username and not self.smtp_password:
            problems.append("SMTP_PASSWORD is required when SMTP_USERNAME is set")
        redirect_uris = [uri.strip() for uri in self.extension_redirect_uris.split(",") if uri.strip()]
        if not redirect_uris:
            problems.append("EXTENSION_REDIRECT_URIS must contain the published extension redirect URI")
        for uri in redirect_uris:
            parsed = urlsplit(uri)
            if (
                parsed.scheme != "https"
                or parsed.hostname is None
                or not re.fullmatch(r"[a-p]{32}\.chromiumapp\.org", parsed.hostname)
                or parsed.path != "/"
                or parsed.query
                or parsed.fragment
                or parsed.username
                or parsed.password
            ):
                problems.append("EXTENSION_REDIRECT_URIS contains an invalid Chrome extension redirect URI")
                break
        if problems:
            raise ValueError("Invalid staging/production configuration: " + "; ".join(problems))
        return self


@lru_cache
def get_settings() -> Settings:
    return Settings()
