"""
Ticket handler agent: reads support email (IMAP) + DB, categorizes with Hermes,
and drafts replies saved to agents/workspace/ticket_drafts/ for admin review.
"""
import sys
import os
import json
import email
import ssl
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from hermes_client import chat, is_available
from agent_memory import recall, reflect

WORKSPACE = Path(__file__).parent / "workspace" / "ticket_drafts"

CATEGORIZE_PROMPT = """\
You are a support ticket classifier for SecureLink, a URL security and threat-scanning platform.

Classify the ticket and draft a professional, helpful reply that:
- Addresses the customer by name if their name appears in the message
- Directly answers their question or acknowledges the issue
- Is signed "SecureLink Support Team"

Output ONLY valid JSON with no markdown fences:
{
  "category": "BUG_REPORT|BILLING|FEATURE_REQUEST|GENERAL|SECURITY",
  "priority": "HIGH|MEDIUM|LOW",
  "summary": "<one sentence summary of the issue>",
  "draft_reply": "<full email reply body>"
}

Category guide:
- BUG_REPORT: app errors, wrong scan results, broken features
- BILLING: subscription, payment, refund, upgrade/downgrade
- FEATURE_REQUEST: new functionality request
- SECURITY: vulnerability report, privacy concern, data issue
- GENERAL: questions, feedback, account help"""


def _load_config():
    try:
        from config import Config
        return Config()
    except Exception:
        return None


def _extract_body(msg) -> str:
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    return payload.decode(part.get_content_charset() or "utf-8", errors="replace")
    payload = msg.get_payload(decode=True)
    if payload:
        return payload.decode(msg.get_content_charset() or "utf-8", errors="replace")
    return ""


def fetch_imap_tickets(config) -> list:
    tickets = []
    if not config or not getattr(config, "SUPPORT_IMAP_HOST", None) \
            or not getattr(config, "SUPPORT_EMAIL_ADDRESS", None) \
            or not getattr(config, "SUPPORT_EMAIL_PASSWORD", None):
        print("  IMAP: not configured (set SUPPORT_IMAP_HOST, SUPPORT_EMAIL_ADDRESS, SUPPORT_EMAIL_PASSWORD in .env)")
        return tickets
    try:
        from imapclient import IMAPClient
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        with IMAPClient(
            config.SUPPORT_IMAP_HOST,
            port=getattr(config, "SUPPORT_IMAP_PORT", 993),
            ssl=True,
            ssl_context=ssl_ctx,
        ) as client:
            client.login(config.SUPPORT_EMAIL_ADDRESS, config.SUPPORT_EMAIL_PASSWORD)
            client.select_folder("INBOX")
            uids = client.search(["UNSEEN"])
            print(f"  IMAP: {len(uids)} unseen message(s)")
            for uid in uids[:20]:
                raw = client.fetch([uid], ["RFC822"])[uid][b"RFC822"]
                msg = email.message_from_bytes(raw)
                tickets.append({
                    "source": "email",
                    "uid": uid,
                    "from": msg.get("From", ""),
                    "subject": msg.get("Subject", "(no subject)"),
                    "body": _extract_body(msg)[:3000],
                    "received": msg.get("Date", ""),
                })
    except Exception as e:
        print(f"  IMAP error: {e}")
    return tickets


def fetch_db_tickets(config) -> list:
    tickets = []
    if not config:
        return tickets
    try:
        from database import Database
        from sqlalchemy import text
        db = Database(config)
        session = db.get_session()
        try:
            rows = session.execute(text(
                "SELECT id, email, subject, message, created_at FROM support_tickets "
                "WHERE (agent_processed IS NULL OR agent_processed = 0) "
                "ORDER BY created_at DESC LIMIT 20"
            )).fetchall()
            print(f"  DB: {len(rows)} unprocessed ticket(s)")
            for r in rows:
                tickets.append({
                    "source": "db",
                    "id": r[0],
                    "from": r[1] or "",
                    "subject": r[2] or "Support Request",
                    "body": (r[3] or "")[:3000],
                    "received": str(r[4]),
                })
        except Exception:
            print("  DB: support_tickets table not found (skipping)")
        session.close()
    except Exception as e:
        print(f"  DB error: {e}")
    return tickets


def categorize_and_draft(ticket: dict) -> dict:
    prompt = (
        f"From: {ticket['from']}\n"
        f"Subject: {ticket['subject']}\n"
        f"Date: {ticket.get('received', '')}\n\n"
        f"{ticket['body']}"
    )
    memory = recall("ticket_handler")
    system = CATEGORIZE_PROMPT + (f"\n\n{memory}" if memory else "")
    raw = chat([
        {"role": "system", "content": system},
        {"role": "user", "content": prompt},
    ])
    try:
        cleaned = raw.strip().lstrip("```json").lstrip("```").rstrip("```").strip()
        return json.loads(cleaned)
    except json.JSONDecodeError:
        return {
            "category": "GENERAL",
            "priority": "MEDIUM",
            "summary": "Hermes parse error — raw output below",
            "draft_reply": raw,
        }


def save_draft(ticket: dict, analysis: dict) -> Path:
    WORKSPACE.mkdir(parents=True, exist_ok=True)
    ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    uid = ticket.get("uid") or ticket.get("id") or ts
    out = WORKSPACE / f"ticket_{uid}_{ts}.json"
    out.write_text(json.dumps({"ticket": ticket, "analysis": analysis,
                               "created_at": datetime.utcnow().isoformat()}, indent=2))
    return out


def main():
    if not is_available():
        print("ERROR: Ollama not running — start with: ollama serve")
        sys.exit(1)

    config = _load_config()
    print("Checking for new tickets...")
    tickets = fetch_imap_tickets(config) + fetch_db_tickets(config)

    if not tickets:
        print("No new tickets found.")
        sys.exit(0)

    print(f"\nProcessing {len(tickets)} ticket(s) with Hermes...\n")
    for t in tickets:
        print("=" * 60)
        print(f"  Source:   {t['source'].upper()}")
        print(f"  From:     {t['from']}")
        print(f"  Subject:  {t['subject']}")
        analysis = categorize_and_draft(t)
        print(f"  Category: {analysis.get('category')}  |  Priority: {analysis.get('priority')}")
        print(f"  Summary:  {analysis.get('summary')}")
        print(f"\n  --- Draft Reply (first 300 chars) ---")
        print(f"  {analysis.get('draft_reply', '')[:300]}...")
        path = save_draft(t, analysis)
        print(f"\n  Saved: {path.name}")

    print(f"\nDrafts saved to agents/workspace/ticket_drafts/")
    print("Use /hermes-tickets to review and send approved replies.")
    reflect("ticket_handler", f"Processed {len(tickets)} ticket(s)", "success")


if __name__ == "__main__":
    main()
