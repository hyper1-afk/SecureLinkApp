"""
Business Analyst agent: scans the codebase, git history, and app patterns
to identify concrete improvement opportunities. Saves a structured recommendation
report to agents/workspace/recommendations/.
"""
import sys
import os
import json
import subprocess
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent))

from hermes_client import chat, is_available
from agent_memory import recall, reflect

PROJECT_ROOT = Path(__file__).parent.parent
WORKSPACE = Path(__file__).parent / "workspace" / "recommendations"

ANALYST_PROMPT = """\
You are a business and technical analyst for SecureLink, a Flask URL security platform.
Review the provided codebase snapshot and identify the top 5 improvements that would:
1. Fix security vulnerabilities or bugs
2. Improve user experience or performance
3. Add high-value missing features (within the existing free/pro/enterprise tier model)

For each recommendation output exactly this block (no markdown headers):

RECOMMENDATION: <short title>
TYPE: BUG_FIX|SECURITY|PERFORMANCE|FEATURE|UX
PRIORITY: HIGH|MEDIUM|LOW
EFFORT: LOW|MEDIUM|HIGH
FILE: <primary file to change>
DESCRIPTION: <specific explanation of the problem>
PROPOSED_CHANGE: <concrete description of what code to add/change/remove>
BUSINESS_VALUE: <why this matters for users or revenue>

Output exactly 5 recommendations."""


def get_git_log(n=30) -> str:
    result = subprocess.run(
        ["git", "log", f"-{n}", "--oneline", "--no-merges"],
        capture_output=True, text=True, cwd=str(PROJECT_ROOT)
    )
    return result.stdout


def get_recent_errors() -> str:
    log_candidates = [PROJECT_ROOT / "logs" / "app.log", PROJECT_ROOT / "app.log"]
    for log_file in log_candidates:
        if log_file.exists():
            lines = log_file.read_text(errors="replace").splitlines()
            errors = [l for l in lines if "ERROR" in l or "CRITICAL" in l]
            return "\n".join(errors[-50:])
    return "(no log file found)"


def get_route_summary() -> str:
    app_py = PROJECT_ROOT / "app.py"
    lines = app_py.read_text(errors="replace").splitlines()
    routes = [l.strip() for l in lines if "@app.route" in l or "def " in l and "route" in l.lower()]
    return "\n".join(routes[:80])


def get_readme_features() -> str:
    readme = PROJECT_ROOT / "README.md"
    if readme.exists():
        content = readme.read_text(errors="replace")
        # Extract the features table section
        start = content.find("| Feature")
        end = content.find("---", start) if start != -1 else -1
        if start != -1:
            return content[start:end if end != -1 else start + 2000]
    return ""


def parse_recommendations(text: str) -> list:
    recs = []
    blocks = text.strip().split("RECOMMENDATION:")
    for block in blocks[1:]:  # Skip empty first split
        rec = {"title": block.split("\n")[0].strip()}
        for field in ["TYPE", "PRIORITY", "EFFORT", "FILE", "DESCRIPTION",
                      "PROPOSED_CHANGE", "BUSINESS_VALUE"]:
            tag = f"{field}:"
            if tag in block:
                val = block.split(tag, 1)[1].split("\n")[0].strip()
                rec[field.lower()] = val
        recs.append(rec)
    return recs


def main():
    if not is_available():
        print("ERROR: Ollama not running — start with: ollama serve")
        sys.exit(1)

    print("Gathering codebase snapshot...")
    git_log = get_git_log()
    errors = get_recent_errors()
    routes = get_route_summary()
    features = get_readme_features()

    context = f"""=== Recent Git Activity (last 30 commits) ===
{git_log}

=== App Routes Summary ===
{routes}

=== Feature Matrix (from README) ===
{features}

=== Recent Error Log ===
{errors}
"""
    print("Sending to Hermes for analysis...")
    memory = recall("business_analyst")
    system = ANALYST_PROMPT + (f"\n\n{memory}" if memory else "")
    result = chat([
        {"role": "system", "content": system},
        {"role": "user", "content": context},
    ], timeout=180)

    print("\n" + "=" * 60)
    print("Business Analysis Report")
    print("=" * 60)
    print(result)

    recs = parse_recommendations(result)

    WORKSPACE.mkdir(parents=True, exist_ok=True)
    date_str = datetime.utcnow().strftime("%Y-%m-%d")
    out_file = WORKSPACE / f"{date_str}.json"
    payload = {
        "generated_at": datetime.utcnow().isoformat(),
        "recommendations": recs,
        "raw_report": result,
    }
    out_file.write_text(json.dumps(payload, indent=2))
    print(f"\nReport saved: agents/workspace/recommendations/{date_str}.json")
    print(f"Found {len(recs)} recommendations.")
    print("Run 'python agents/run_agent.py implement' to action the top recommendation.")
    reflect("business_analyst", result, "success" if recs else "skipped")

    _send_report_email(date_str, recs, result)


def _send_report_email(date_str: str, recs: list, raw_report: str):
    try:
        from config import Config
        cfg = Config()
        if not getattr(cfg, "SMTP_USERNAME", None) or not getattr(cfg, "SMTP_PASSWORD", None):
            print("  Email: SMTP not configured — skipping report email")
            return

        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText

        priority_colors = {"HIGH": "#ef4444", "MEDIUM": "#f59e0b", "LOW": "#10b981"}

        rows = ""
        for i, r in enumerate(recs, 1):
            color = priority_colors.get(r.get("priority", "LOW"), "#6b7280")
            rows += f"""
            <tr>
              <td style="padding:8px;border-bottom:1px solid #e5e7eb;font-weight:600">{i}. {r.get('title','')}</td>
              <td style="padding:8px;border-bottom:1px solid #e5e7eb">
                <span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;font-size:12px">{r.get('priority','')}</span>
              </td>
              <td style="padding:8px;border-bottom:1px solid #e5e7eb">{r.get('type','')}</td>
              <td style="padding:8px;border-bottom:1px solid #e5e7eb">{r.get('file','')}</td>
            </tr>
            <tr>
              <td colspan="4" style="padding:4px 8px 12px 8px;color:#6b7280;font-size:13px">{r.get('description','')}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html><body style="font-family:sans-serif;max-width:700px;margin:0 auto;padding:20px;color:#1f2937">
  <div style="background:#1e293b;padding:20px;border-radius:8px 8px 0 0">
    <h1 style="color:#fff;margin:0;font-size:20px">SecureLink Business Analysis Report</h1>
    <p style="color:#94a3b8;margin:4px 0 0">{date_str} &mdash; {len(recs)} recommendation(s) generated by Hermes AI</p>
  </div>
  <div style="border:1px solid #e5e7eb;border-top:none;border-radius:0 0 8px 8px;padding:20px">
    <table width="100%" cellpadding="0" cellspacing="0" style="border-collapse:collapse">
      <thead>
        <tr style="background:#f8fafc">
          <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Recommendation</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Priority</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">Type</th>
          <th style="padding:8px;text-align:left;border-bottom:2px solid #e5e7eb">File</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>
    <hr style="border:none;border-top:1px solid #e5e7eb;margin:20px 0">
    <h3 style="color:#374151">Full Report</h3>
    <pre style="background:#f8fafc;padding:16px;border-radius:6px;font-size:12px;white-space:pre-wrap;overflow-x:auto">{raw_report[:4000]}</pre>
    <p style="color:#9ca3af;font-size:12px;margin-top:20px">
      Generated by SecureLink Business Analyst Agent &mdash; report saved to agents/workspace/recommendations/{date_str}.json
    </p>
  </div>
</body></html>"""

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"[SecureLink AI] Business Analysis Report — {date_str} ({len(recs)} recommendations)"
        msg["From"] = getattr(cfg, "SMTP_FROM_EMAIL", None) or "support@securelinkapp.com"
        msg["To"] = "admin@securelinkapp.com"
        msg.attach(MIMEText(html, "html"))

        smtp_host = cfg.SMTP_HOST
        smtp_port = int(getattr(cfg, "SMTP_PORT", 587))

        if getattr(cfg, "SMTP_USE_SSL", False) or smtp_port == 465:
            with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                server.login(cfg.SMTP_USERNAME, cfg.SMTP_PASSWORD)
                server.send_message(msg)
        else:
            with smtplib.SMTP(smtp_host, smtp_port) as server:
                server.starttls()
                server.login(cfg.SMTP_USERNAME, cfg.SMTP_PASSWORD)
                server.send_message(msg)

        print(f"  Report emailed to admin@securelinkapp.com")
    except Exception as e:
        print(f"  Email error (report still saved locally): {e}")


if __name__ == "__main__":
    main()
