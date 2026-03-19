# SecureLink — Self-Hosted URL Security Platform

SecureLink is an open-source security platform you can deploy on your own server or network. It scans URLs for phishing, malware, and other threats; monitors domain health (SSL, SPF, DMARC); checks emails for breached credentials; and ships a browser extension that auto-scans every page you visit — all pointed at your own infrastructure.

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![Docker](https://img.shields.io/badge/Docker-Compose-blue.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

---

## Features

| Feature | Free tier | Pro tier | Enterprise |
|---------|-----------|----------|------------|
| URL threat scanning | ✅ | ✅ | ✅ |
| Browser extension (auto-scan) | ✅ | ✅ | ✅ |
| Domain health check (SSL/SPF/DMARC) | ✅ | ✅ | ✅ |
| Security news feed | ✅ | ✅ | ✅ |
| Email breach lookup | ✅ limited | ✅ full | ✅ full |
| Dark web monitoring | — | ✅ | ✅ |
| Safe link shortener | — | ✅ | ✅ |
| Health check PDF export | — | ✅ | ✅ |
| Domain score drop alerts | — | ✅ | ✅ |
| Attack surface monitor | — | — | ✅ |
| Organization / team dashboard | — | — | ✅ |
| Compliance center | — | — | ✅ |

---

## Quick Start (Docker)

The fastest path to a running instance.

### Prerequisites

- Docker 24+ and Docker Compose v2
- A domain name pointed at your server (for HTTPS)

### 1. Clone and configure

```bash
git clone https://github.com/your-org/securelink.git
cd securelink
cp .env.docker.example .env
```

Edit `.env` — at minimum fill in the **Required** section:

```env
SECRET_KEY=        # generate: python -c "import secrets; print(secrets.token_hex(32))"
ADMIN_SECRET_KEY=  # separate key for admin operations
FERNET_ENCRYPTION_KEY=  # generate: python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
POSTGRES_USER=securelink
POSTGRES_PASSWORD=change_this_strong_password
POSTGRES_DB=securelink
APP_URL=https://yourdomain.com
APP_NAME=SecureLink   # customize your instance name
```

### 2. Start the stack

```bash
docker compose up -d
```

The app binds to `127.0.0.1:5000` by default. Put Nginx or Caddy in front of it for HTTPS (see [Reverse Proxy](#reverse-proxy-nginx) below).

### 3. Create the first admin account

```bash
docker compose exec web python manage_admins.py
```

---

## Manual / Local Setup (without Docker)

### Prerequisites

- Python 3.11+
- PostgreSQL 14+ (or SQLite for local dev)

### Install

```bash
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env
# edit .env with your values
python app.py
```

Open **http://localhost:5000**.

For SQLite (no Postgres needed for local dev), leave `DATABASE_URL` empty — the app falls back to `link_verifier.db`.

---

## Reverse Proxy (Nginx)

An `nginx.conf` is included at the root of the repo. Edit the `server_name` and certificate paths, then:

```bash
# Point Docker port to localhost only (default), then:
sudo cp nginx.conf /etc/nginx/sites-available/securelink
sudo ln -s /etc/nginx/sites-available/securelink /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

For automatic SSL with Let's Encrypt:

```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d yourdomain.com
```

---

## Browser Extension

The extension ships with `https://securelinkapp.com` as its default API endpoint. When self-hosting, point it at your own server.

### Option A — Use the Settings tab (easiest)

1. Load the `browser-extension/` folder as an unpacked extension in Chrome (`chrome://extensions` → Load unpacked)
2. Click the extension icon → **⚙ Settings** tab
3. Enter your server URL (e.g. `https://yourdomain.com`) and click **Save**
4. The extension will now send all scans to your server

### Option B — Build with your URL baked in

Edit `browser-extension/background.js` line 4:

```js
const API_BASE = 'https://yourdomain.com';
```

Then zip the `browser-extension/` folder and sideload or publish to the Chrome Web Store.

---

## Environment Variables Reference

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRET_KEY` | ✅ | Flask session secret (generate randomly) |
| `ADMIN_SECRET_KEY` | ✅ | Admin operations secret |
| `FERNET_ENCRYPTION_KEY` | ✅ | Fernet key for encrypted fields |
| `APP_URL` | ✅ | Your public URL, e.g. `https://yourdomain.com` |
| `APP_NAME` | — | Instance display name (default: `SecureLink`) |
| `POSTGRES_USER` | ✅ (Docker) | PostgreSQL username |
| `POSTGRES_PASSWORD` | ✅ (Docker) | PostgreSQL password |
| `POSTGRES_DB` | ✅ (Docker) | PostgreSQL database name |
| `DATABASE_URL` | — | Full Postgres URL (overrides above) |
| `STRIPE_SECRET_KEY` | — | Stripe secret key (for paid tiers) |
| `STRIPE_PUBLISHABLE_KEY` | — | Stripe publishable key |
| `STRIPE_WEBHOOK_SECRET` | — | Stripe webhook signing secret |
| `GOOGLE_CLIENT_ID` | — | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | — | Google OAuth client secret |
| `VIRUSTOTAL_API_KEY` | — | VirusTotal API key (enhanced scanning) |
| `GOOGLE_SAFE_BROWSING_API_KEY` | — | Google Safe Browsing API key |
| `HIBP_API_KEY` | — | Have I Been Pwned API key (breach checks) |
| `SMTP_HOST` | — | SMTP server hostname |
| `SMTP_PORT` | — | SMTP port (587 for STARTTLS, 465 for SSL) |
| `SMTP_USERNAME` | — | SMTP username |
| `SMTP_PASSWORD` | — | SMTP password |
| `SMTP_FROM_EMAIL` | — | From address for outgoing emails |
| `NEWS_API_KEY` | — | NewsAPI key (security news feed) |
| `LOG_LEVEL` | — | `DEBUG` / `INFO` / `WARNING` (default: `INFO`) |

### Which API keys do you actually need?

- **Bare minimum (no external APIs):** The scanner runs on heuristics, SSL checks, DNS, and WHOIS lookups with zero external API keys. Most threats are caught without them.
- **Recommended:** `VIRUSTOTAL_API_KEY` (free tier: 4 lookups/min) significantly improves detection.
- **For breach checking:** `HIBP_API_KEY` — requires a paid HIBP subscription (~$4/month).
- **For paid user tiers:** Stripe keys. Leave blank to run free-only mode.
- **For social login:** Google OAuth keys.

---

## Architecture

```
browser-extension/      Chrome/Edge extension (scans URLs via your API)
app.py                  Flask application (routes, auth, API endpoints)
link_verifier.py        Core URL analysis engine (heuristics + external APIs)
domain_scanner.py       Domain health checks (SSL, SPF, DMARC, headers)
database.py             SQLAlchemy models + migrations (PostgreSQL / SQLite)
attack_surface_db.py    Attack surface monitoring database
auth.py                 JWT auth, password hashing, session management
scan_scheduler.py       Background scheduler (weekly reports, score alerts)
templates/              Jinja2 HTML templates
static/                 CSS, JS, images
Dockerfile              Production multi-stage Docker image
docker-compose.yml      Full stack (app + PostgreSQL)
nginx.conf              Sample Nginx reverse proxy config
```

---

## Upgrade / Data Migration

The app runs SQLAlchemy migrations automatically on startup. New columns are added with `ADD COLUMN IF NOT EXISTS` so existing data is never lost. No manual migration steps needed for minor version upgrades.

For major version upgrades, check the `CHANGELOG.md` for any breaking schema changes before updating.

---

## Security Hardening (Production)

- Generate all secret keys with `secrets.token_hex(32)` — never use defaults
- Set `FLASK_ENV=production` and `DEBUG=false`
- Bind Docker to `127.0.0.1` only and terminate TLS at Nginx/Caddy
- Enable Nginx rate limiting (see `nginx.conf` comments)
- Keep PostgreSQL on the internal Docker network — never expose port 5432
- Rotate `SECRET_KEY` only during planned maintenance (invalidates all sessions)

---

## API Reference

All endpoints accept and return JSON. Authenticated endpoints require `Authorization: Bearer <token>`.

| Endpoint | Method | Auth | Description |
|----------|--------|------|-------------|
| `/api/verify` | POST | No | Verify a URL |
| `/api/extension/verify` | POST | Optional | Extension URL scan |
| `/api/extension/auth` | POST | No | Extension login |
| `/api/extension/status` | GET | Optional | Extension session status |
| `/api/stats` | GET | Optional | Scan statistics (per-user when authed) |
| `/api/health-check` | POST | No | Domain health check |
| `/api/breach/email` | POST | Pro | Full breach lookup |
| `/api/public/breach-check` | POST | No | Limited breach check (count only) |
| `/api/reports/health-check-pdf` | POST | Pro | Export health check PDF |
| `/api/health-check/watch` | POST/DELETE | Pro | Watch domain for score drops |
| `/api/health-check/watches` | GET | Pro | List watched domains |

---

## Contributing

Pull requests are welcome. For significant changes, open an issue first to discuss the approach.

```bash
# Run locally in dev mode
FLASK_ENV=development DEBUG=true python app.py
```

---

## License

MIT License — see [LICENSE](LICENSE) for details.
