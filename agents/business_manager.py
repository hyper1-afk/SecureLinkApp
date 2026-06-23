"""
Business Manager agent: reviews a pending pipeline change (diff + test results),
writes a business summary using Hermes, then sends an HTML approval email to
admin@securelinkapp.com with Approve/Deny buttons.
"""
import sys
import os
import json
import smtplib
import ssl
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from hermes_client import chat, is_available

PROJECT_ROOT = Path(__file__).parent.parent
PENDING_DIR = Path(__file__).parent / "workspace" / "pending_changes"

ADMIN_EMAIL = "admin@securelinkapp.com"

REVIEW_PROMPT = """\
You are the Business Manager for SecureLink. Review a proposed code change and write
a clear, concise executive summary for the admin who will approve or deny it.

Your summary must include:
1. What the change does (plain English, no jargon)
2. Why it was recommended (business value)
3. Test status and confidence level
4. Any risks or concerns
5. Your recommendation: APPROVE or DENY with brief reasoning

Keep it under 250 words. Write for a non-technical decision maker."""


def load_pending(token: str) -> dict:
    f = PENDING_DIR / f"{token}.json"
    if not f.exists():
        raise FileNotFoundError(f"No pending change found for token: {token}")
    return json.loads(f.read_text())


def load_config():
    try:
        from config import Config
        return Config()
    except Exception:
        return None


def generate_summary(change: dict) -> str:
    rec = change.get("recommendation", {})
    context = (
        f"Recommendation: {rec.get('title')}\n"
        f"Type: {rec.get('type')}  |  Priority: {rec.get('priority')}\n"
        f"Business value: {rec.get('business_value', 'N/A')}\n\n"
        f"Changes made in branch: {change.get('branch')}\n\n"
        f"Git diff (first 2000 chars):\n{change.get('diff', '')[:2000]}\n\n"
        f"Test results: {'PASSED' if change.get('test_passed') else 'FAILED'}\n"
        f"{change.get('test_output', '')[:800]}"
    )
    return chat([
        {"role": "system", "content": REVIEW_PROMPT},
        {"role": "user", "content": context},
    ])


def build_email_html(change: dict, summary: str, app_url: str, token: str) -> str:
    rec = change.get("recommendation", {})
    test_badge = (
        '<span style="color:#16a34a;font-weight:bold;">PASSED</span>'
        if change.get("test_passed")
        else '<span style="color:#dc2626;font-weight:bold;">FAILED</span>'
    )
    approve_url = f"{app_url}/api/pipeline/review?token={token}&action=approve"
    deny_url = f"{app_url}/api/pipeline/review?token={token}&action=deny"

    return f"""<!DOCTYPE html>
<html>
<head><meta charset="utf-8"></head>
<body style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;padding:24px;color:#1f2937;">
  <div style="background:#1e3a5f;padding:20px;border-radius:8px 8px 0 0;">
    <h1 style="color:#fff;margin:0;font-size:20px;">SecureLink Pipeline — Change Review Required</h1>
  </div>
  <div style="border:1px solid #e5e7eb;border-top:none;padding:24px;border-radius:0 0 8px 8px;">

    <h2 style="color:#1e3a5f;font-size:16px;margin-top:0;">
      {rec.get('title', 'Automated Change')}
    </h2>
    <p style="color:#6b7280;font-size:13px;margin-top:-8px;">
      Type: <strong>{rec.get('type','')}</strong> &nbsp;|&nbsp;
      Priority: <strong>{rec.get('priority','')}</strong> &nbsp;|&nbsp;
      Branch: <code style="background:#f3f4f6;padding:2px 6px;border-radius:3px;">{change.get('branch','')}</code> &nbsp;|&nbsp;
      Tests: {test_badge}
    </p>

    <h3 style="font-size:14px;color:#374151;">Business Manager Summary</h3>
    <div style="background:#f9fafb;border-left:4px solid #1e3a5f;padding:12px 16px;
                border-radius:0 4px 4px 0;font-size:14px;line-height:1.6;white-space:pre-wrap;">{summary}</div>

    <h3 style="font-size:14px;color:#374151;">Changes Preview (git diff)</h3>
    <pre style="background:#0f172a;color:#e2e8f0;padding:16px;border-radius:6px;
               font-size:12px;overflow-x:auto;white-space:pre-wrap;">{change.get('diff','(no diff)')[:3000]}</pre>

    <div style="margin-top:32px;text-align:center;">
      <a href="{approve_url}"
         style="display:inline-block;background:#16a34a;color:#fff;padding:14px 32px;
                border-radius:6px;text-decoration:none;font-size:15px;font-weight:bold;margin-right:16px;">
        Approve &amp; Deploy
      </a>
      <a href="{deny_url}"
         style="display:inline-block;background:#dc2626;color:#fff;padding:14px 32px;
                border-radius:6px;text-decoration:none;font-size:15px;font-weight:bold;">
        Deny Changes
      </a>
    </div>
    <p style="text-align:center;font-size:11px;color:#9ca3af;margin-top:16px;">
      This link is single-use. Clicking Approve will merge the branch and push to production.
    </p>
  </div>
  <p style="font-size:11px;color:#9ca3af;text-align:center;margin-top:16px;">
    SecureLink Autonomous Pipeline &mdash; {datetime.utcnow().strftime('%Y-%m-%d %H:%M')} UTC
  </p>
</body>
</html>"""


def send_approval_email(config, token: str, rec_title: str, html_body: str) -> bool:
    if not config or not getattr(config, "SMTP_HOST", None):
        print("  SMTP not configured — cannot send approval email.")
        return False
    try:
        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SecureLink Pipeline] Review Required: {rec_title}"
        msg["From"] = getattr(config, "SMTP_FROM_EMAIL", "noreply@securelinkapp.com")
        msg["To"] = ADMIN_EMAIL
        msg.attach(MIMEText(html_body, "html"))

        port = getattr(config, "SMTP_PORT", 587)
        use_ssl = getattr(config, "SMTP_USE_SSL", False)
        use_tls = getattr(config, "SMTP_USE_TLS", True)

        if use_ssl:
            ctx = ssl.create_default_context()
            with smtplib.SMTP_SSL(config.SMTP_HOST, port, context=ctx) as s:
                s.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                s.send_message(msg)
        else:
            with smtplib.SMTP(config.SMTP_HOST, port, timeout=30) as s:
                if use_tls:
                    s.starttls(context=ssl.create_default_context())
                if config.SMTP_USERNAME:
                    s.login(config.SMTP_USERNAME, config.SMTP_PASSWORD)
                s.send_message(msg)
        return True
    except Exception as e:
        print(f"  Email send failed: {e}")
        return False


def update_pending_status(token: str, update: dict):
    f = PENDING_DIR / f"{token}.json"
    data = json.loads(f.read_text())
    data.update(update)
    f.write_text(json.dumps(data, indent=2))


def main():
    if len(sys.argv) < 2:
        # List pending changes if no token given
        files = list(PENDING_DIR.glob("*.json")) if PENDING_DIR.exists() else []
        if not files:
            print("No pending changes. Run: python agents/run_agent.py implement")
            sys.exit(0)
        print(f"Pending changes ({len(files)}):")
        for f in sorted(files):
            d = json.loads(f.read_text())
            print(f"  {d.get('token','?')[:16]}...  "
                  f"status={d.get('status','?')}  "
                  f"rec={d.get('recommendation',{}).get('title','?')}")
        sys.exit(0)

    token = sys.argv[1]

    if not is_available():
        print("ERROR: Ollama not running — start with: ollama serve")
        sys.exit(1)

    change = load_pending(token)
    rec = change.get("recommendation", {})
    config = load_config()
    app_url = getattr(config, "APP_URL", "https://securelinkapp.com") if config else "https://securelinkapp.com"

    print(f"\nBusiness Manager reviewing: {rec.get('title')}")
    print("Generating executive summary with Hermes...")
    summary = generate_summary(change)

    print("\n" + "=" * 60)
    print("Executive Summary")
    print("=" * 60)
    print(summary)

    html = build_email_html(change, summary, app_url, token)

    # Save the summary to the pending file
    update_pending_status(token, {
        "manager_summary": summary,
        "manager_reviewed_at": datetime.utcnow().isoformat(),
        "status": "awaiting_admin_approval",
    })

    print(f"\nSending approval email to {ADMIN_EMAIL}...")
    sent = send_approval_email(config, token, rec.get("title", "Change"), html)
    if sent:
        print(f"Approval email sent. Waiting for admin decision.")
        print(f"Token: {token}")
    else:
        print(f"\nSMTP not available. Admin can manually approve via:")
        print(f"  {app_url}/api/pipeline/review?token={token}&action=approve")
        print(f"  {app_url}/api/pipeline/review?token={token}&action=deny")


if __name__ == "__main__":
    main()
