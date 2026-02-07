# SecureLinkApp - Deployment Guide

## 🚀 Quick Start Deployment

This guide covers deploying SecureLinkApp to production. We recommend **Railway** or **Render** for easy deployment.

---

## 📋 Pre-Deployment Checklist

### 1. Stripe Setup (Required for Payments)
1. Go to [Stripe Dashboard](https://dashboard.stripe.com)
2. Switch from Test to **Live Mode**
3. Get your **Live API Keys**:
   - `STRIPE_SECRET_KEY` (starts with `sk_live_`)
   - `STRIPE_PUBLISHABLE_KEY` (starts with `pk_live_`)
4. Create your products/prices in Stripe Dashboard
5. Set up a **Webhook** pointing to `https://yourdomain.com/webhook/stripe`
   - Get the `STRIPE_WEBHOOK_SECRET` (starts with `whsec_`)

### 2. Google OAuth Setup
1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Update your OAuth consent screen for production
3. Add your production domain to **Authorized JavaScript origins**:
   - `https://securelinkapp.com`
4. Add **Authorized redirect URIs**:
   - `https://securelinkapp.com/auth/callback/google`

### 3. Domain Setup
1. Register your domain at [Cloudflare](https://cloudflare.com)
2. Point DNS to your hosting provider
3. Enable SSL/HTTPS (usually automatic)

---

## 🚂 Deploy to Railway (Recommended)

### Step 1: Create Railway Account
1. Go to [Railway.app](https://railway.app)
2. Sign up with GitHub

### Step 2: Connect Repository
1. Push your code to GitHub (make sure `.env` is NOT committed!)
2. In Railway, click **New Project** → **Deploy from GitHub repo**
3. Select your repository

### Step 3: Add PostgreSQL Database
1. In your Railway project, click **+ New** → **Database** → **PostgreSQL**
2. Railway automatically sets `DATABASE_URL`

### Step 4: Set Environment Variables
In Railway Dashboard → Your Project → **Variables**, add:

```
SECRET_KEY=<generate with: python -c "import secrets; print(secrets.token_hex(32))">
DEBUG=False
FLASK_ENV=production
APP_URL=https://your-app.railway.app

# Stripe Live Keys
STRIPE_SECRET_KEY=sk_live_xxxxx
STRIPE_PUBLISHABLE_KEY=pk_live_xxxxx
STRIPE_WEBHOOK_SECRET=whsec_xxxxx

# Google OAuth
GOOGLE_CLIENT_ID=xxxxx.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=xxxxx

# Email (optional)
EMAIL_HOST=imap.gmail.com
EMAIL_PORT=993
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password
```

### Step 5: Deploy
Railway automatically deploys when you push to GitHub!

### Step 6: Custom Domain
1. Go to **Settings** → **Domains**
2. Add your custom domain
3. Update DNS at Cloudflare

---

## 🎨 Deploy to Render

### Step 1: Create Render Account
1. Go to [Render.com](https://render.com)
2. Sign up with GitHub

### Step 2: Create Web Service
1. Click **New** → **Web Service**
2. Connect your GitHub repository
3. Configure:
   - **Name**: securelinkapp
   - **Environment**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `gunicorn app:app`

### Step 3: Add PostgreSQL
1. Click **New** → **PostgreSQL**
2. Copy the **Internal Database URL**

### Step 4: Set Environment Variables
In **Environment** tab, add all the same variables as Railway (above).

### Step 5: Deploy
Click **Create Web Service** - Render deploys automatically!

---

## � Deploy with Docker (VM / Self-Hosted)

Use Docker to run SecureLinkApp on any VM or self-hosted server.

### Prerequisites
- Docker and Docker Compose installed
- A VM or server with at least 1GB RAM

### Step 1: Configure Environment
```bash
# Copy the example environment file
cp .env.docker.example .env

# Edit with your values
nano .env
```

**Required settings:**
- `SECRET_KEY` - Generate with: `python -c "import secrets; print(secrets.token_hex(32))"`
- `POSTGRES_PASSWORD` - Set a strong database password
- `APP_URL` - Your server's URL (e.g., `https://yourdomain.com`)
- Stripe keys if using payments

### Step 2: Build and Run
```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Check status
docker-compose ps
```

### Step 3: Verify Installation
```bash
# Check if app is running
curl http://localhost:5000

# View container health
docker-compose ps
```

### Useful Commands
```bash
# Stop all services
docker-compose down

# Rebuild after code changes
docker-compose up -d --build

# View logs for specific service
docker-compose logs -f web

# Access database
docker-compose exec db psql -U securelink -d securelink

# Backup database
docker-compose exec db pg_dump -U securelink securelink > backup.sql

# Restore database
cat backup.sql | docker-compose exec -T db psql -U securelink -d securelink
```

### Production Recommendations
1. **Use a reverse proxy** (Nginx/Caddy) for SSL termination
2. **Enable firewall** - only expose ports 80/443
3. **Set up backups** for the PostgreSQL volume
4. **Monitor resources** with `docker stats`

---

## �🔐 Important Security Notes

### Never Commit Secrets
Ensure these are in `.gitignore`:
```
.env
.env.local
.env.production
```

### Rotate Compromised Keys
If you accidentally commit API keys:
1. **Immediately** regenerate all keys in respective dashboards
2. Update environment variables in your hosting provider
3. Remove from Git history (or consider the old keys compromised forever)

### Generate Secure SECRET_KEY
```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

---

## 📊 Post-Deployment Tasks

### 1. Test Everything
- [ ] User registration/login works
- [ ] Google OAuth works
- [ ] Link verification works
- [ ] Payments process correctly (use Stripe test mode first!)
- [ ] Webhooks receive events
- [ ] Emails send correctly

### 2. Set Up Monitoring
- Enable Railway/Render logging
- Consider adding [Sentry](https://sentry.io) for error tracking

### 3. Set Up Stripe Webhooks
1. In Stripe Dashboard → Developers → Webhooks
2. Add endpoint: `https://yourdomain.com/webhook/stripe`
3. Select events:
   - `checkout.session.completed`
   - `customer.subscription.created`
   - `customer.subscription.updated`
   - `customer.subscription.deleted`
   - `invoice.payment_succeeded`
   - `invoice.payment_failed`

### 4. Update OAuth Redirect URIs
Make sure Google OAuth has your production URL:
- `https://securelinkapp.com/auth/callback/google`

---

## 🔧 Troubleshooting

### App Won't Start
- Check logs in Railway/Render dashboard
- Verify all required environment variables are set
- Ensure `SECRET_KEY` is set

### Database Errors
- Verify `DATABASE_URL` is set correctly
- Check PostgreSQL is running
- Run migrations if needed

### OAuth Errors
- Verify redirect URIs match exactly
- Check client ID/secret are correct
- Ensure OAuth consent screen is configured

### Payment Errors
- Verify you're using LIVE keys (not test)
- Check webhook secret is correct
- Review Stripe dashboard for failed events

---

## 📁 File Structure for Production

```
SecureLinkApp/
├── app.py              # Main application
├── config.py           # Configuration (uses env vars only)
├── database.py         # Database models
├── auth.py             # Authentication
├── payments.py         # Stripe integration
├── oauth.py            # OAuth providers
├── link_verifier.py    # Core verification logic
├── cyber_news.py       # News feed
├── email_monitor.py    # Email scanning
├── notifications.py    # Alert system
├── weekly_reports.py   # Report generation
├── requirements.txt    # Dependencies
├── Procfile            # Gunicorn config
├── runtime.txt         # Python version
├── .gitignore          # Git ignore rules
├── .env.example        # Environment template
└── templates/          # HTML templates
    ├── index.html
    ├── login.html
    └── profile.html
```

---

## 💰 Estimated Costs

| Service | Free Tier | Paid |
|---------|-----------|------|
| Railway | 500 hours/month | $5/month |
| Render | 750 hours/month | $7/month |
| PostgreSQL | Included | Included |
| Cloudflare | Free | Free |
| Stripe | 2.9% + 30¢ per transaction | Same |

---

## 🆘 Need Help?

- Railway Docs: https://docs.railway.app
- Render Docs: https://render.com/docs
- Stripe Docs: https://stripe.com/docs
- Flask Docs: https://flask.palletsprojects.com

Good luck with your launch! 🎉
