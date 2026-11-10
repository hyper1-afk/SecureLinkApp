from __future__ import annotations

import base64
import secrets
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENV_EXAMPLE = ROOT / ".env.example"
ENV_FILE = ROOT / ".env"


def main() -> None:
    if ENV_FILE.exists():
        raise SystemExit(".env already exists; preserve it and edit it manually if needed.")

    content = ENV_EXAMPLE.read_text(encoding="utf-8")
    database_password = secrets.token_hex(24)
    app_secret = secrets.token_hex(32)
    encryption_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii")

    replacements = {
        "APP_PUBLIC_URL": "http://localhost:8000",
        "APP_SECRET_KEY": app_secret,
        "EMAIL_OUTBOX_ENCRYPTION_KEY": encryption_key,
        "MFA_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
        "DATABASE_URL": (
            "postgresql+psycopg://securelink:"
            f"{database_password}@postgres:5432/securelink"
        ),
        "SMTP_HOST": "mailpit",
        "SMTP_PORT": "1025",
        "SMTP_FROM_EMAIL": "no-reply@securelink.test",
        "SMTP_STARTTLS": "false",
        "CORS_ORIGINS": "http://localhost:8000",
    }

    lines = content.splitlines()
    for key, value in replacements.items():
        prefix = f"{key}="
        for index, line in enumerate(lines):
            if line.startswith(prefix):
                lines[index] = prefix + value
                break
        else:
            lines.append(prefix + value)
    lines.append(f"POSTGRES_PASSWORD={database_password}")
    ENV_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("Created .env with unique local-only secrets. Do not commit this file.")


if __name__ == "__main__":
    main()
