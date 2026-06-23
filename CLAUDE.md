# SecureLink — Claude Code Project Guide

## Project overview
Flask URL security platform. Scans URLs for threats, checks domain health (SSL/SPF/DMARC), monitors breached credentials, and ships a Chrome extension. Stack: Python 3.11, Flask, SQLAlchemy, PostgreSQL (SQLite for local dev).

## Running locally
```powershell
.venv\Scripts\python.exe app.py        # SQLite fallback if DATABASE_URL is unset
# or
FLASK_ENV=development python app.py
```
App runs on http://localhost:5000.

## Key files
| File | Purpose |
|------|---------|
| `app.py` | Flask routes, auth endpoints, API |
| `link_verifier.py` | URL threat analysis engine |
| `domain_scanner.py` | SSL / SPF / DMARC / header checks |
| `database.py` | SQLAlchemy models, migrations |
| `auth.py` | JWT, password hashing, sessions |
| `scan_scheduler.py` | Background scheduler (weekly reports) |
| `agents/` | Hermes LLM automation scripts |

## Autonomous pipeline agents (Hermes-3 via Ollama)

### Autonomous improvement pipeline
```
Business Analyst  →  finds improvement opportunities (analyze)
       ↓
Update Agent      →  implements on a new git branch (implement)
       ↓
Test Suite        →  runs pytest automatically
       ↓
Business Manager  →  writes executive summary + sends approval email
       ↓
Admin email       →  [Approve & Deploy] or [Deny] buttons
       ↓
Deploy Agent      →  merges to main, pushes to production
```

Run the full pipeline: `python agents/run_agent.py pipeline`  
Or use `/hermes-pipeline` from inside Claude Code.

### Support ticket system
- `python agents/run_agent.py tickets` — reads IMAP + DB, Hermes categorizes + drafts reply
- Drafts saved to `agents/workspace/ticket_drafts/` for admin review
- Use `/hermes-tickets` to review and send approved replies

### Business analysis
- `python agents/run_agent.py analyze` — scans codebase + git log, produces recommendations
- Reports saved to `agents/workspace/recommendations/YYYY-MM-DD.json`
- Use `/hermes-analyze` to view recommendations and choose what to implement

### Workspace (runtime state — gitignored)
```
agents/workspace/
  recommendations/      # Business analyst output
  pending_changes/      # Changes awaiting admin approval (token-keyed JSON)
  ticket_drafts/        # Hermes-drafted ticket replies
```

### Flask approval endpoint
`GET /api/pipeline/review?token=XXX&action=approve|deny`  
Links are embedded in the Business Manager approval email. Token is 32-byte random, single-use.

## Hermes agents (NousResearch Hermes-3 via Ollama)

These scripts run a local free LLM for bug detection, code review, and test analysis.

### One-time setup
1. Download and install Ollama from https://ollama.com/download  
2. In a terminal: `ollama pull hermes3`  
3. Ollama auto-starts as a background service on Windows after install.

### Commands
```powershell
# Check Ollama + model status
python agents/run_agent.py status

# Scan core files for bugs
python agents/run_agent.py fix-bugs

# Scan specific files
python agents/run_agent.py fix-bugs app.py link_verifier.py

# Review current git diff before pushing
python agents/run_agent.py review

# Run tests and auto-diagnose failures
python agents/run_agent.py test
```

### Custom slash commands (Claude Code)
- `/hermes-review` — trigger Hermes diff review from inside Claude Code
- `/hermes-fix` — scan core files for bugs and offer to apply fixes

### Pre-push gate
`.git/hooks/pre-push` auto-runs Hermes review on every `git push`.  
- **BLOCK verdict** → push is rejected (CRITICAL security issue found)  
- **REQUEST_CHANGES** → asks whether to proceed  
- **APPROVE** or Ollama down → push proceeds  

To bypass once: `git push --no-verify`

## Security rules
- Never commit secrets, API keys, or credentials (SMTP passwords, Stripe keys, etc.)
- All user input must be validated at `/api/*` route boundaries — not inside services
- JWT validation lives in `auth.py` — do not duplicate or bypass it
- SQL queries go through SQLAlchemy ORM — never raw f-string queries
- `test_smtp.py` in the project root contains a hardcoded SMTP password — do NOT commit it

## Testing
```powershell
python -m pytest -x --tb=short   # stop on first failure
python agents/run_agent.py test   # same + Hermes failure analysis
```
