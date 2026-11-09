import smtplib
import ssl
from email.message import EmailMessage
from urllib.parse import urlencode

from apps.api.config import get_settings


def email_delivery_configured() -> bool:
    settings = get_settings()
    valid_transport = (
        settings.app_env != "production"
        or (settings.app_public_url.startswith("https://") and settings.smtp_starttls)
    )
    return bool(settings.smtp_host and settings.smtp_from_email and valid_transport)


def send_action_email(purpose: str, recipient: str, token: str) -> None:
    settings = get_settings()
    if not email_delivery_configured():
        raise RuntimeError("Secure SMTP email delivery is not configured")
    if purpose == "verify_email":
        path = "/verify-email"
        subject = "Verify your SecureLink email"
        action = "verify your email address"
    elif purpose == "reset_password":
        path = "/reset-password"
        subject = "Reset your SecureLink password"
        action = "reset your password"
    else:
        raise ValueError("Unsupported account email action")

    action_url = f"{settings.app_public_url.rstrip('/')}{path}?{urlencode({'token': token})}"
    message = EmailMessage()
    message["From"] = settings.smtp_from_email
    message["To"] = recipient
    message["Subject"] = subject
    message.set_content(
        f"Use this link to {action}. The link expires shortly and can only be used once.\n\n"
        f"{action_url}\n\n"
        "If you did not request this, you can ignore this message."
    )

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as client:
        if settings.smtp_starttls:
            client.starttls(context=ssl.create_default_context())
        if settings.smtp_username:
            client.login(settings.smtp_username, settings.smtp_password or "")
        client.send_message(message)
