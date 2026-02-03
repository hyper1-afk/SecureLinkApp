# SecureLink 🔒

An AI-powered application that verifies URLs for potential security threats. It monitors your email inbox for suspicious links and allows you to manually paste and check any URL.

![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## Features ✨

- **Manual Link Verification**: Paste any URL to instantly check if it's safe
- **Email Monitoring**: Automatically scan incoming emails for suspicious links
- **Desktop Notifications**: Get alerted immediately when a dangerous link is detected
- **Multi-Layer Analysis**:
  - URL structure analysis (suspicious patterns, encoding tricks)
  - Domain reputation checking (typosquatting, brand impersonation)
  - SSL/TLS certificate validation
  - DNS verification
  - WHOIS domain age checking
  - VirusTotal API integration (optional)
  - Google Safe Browsing API (optional)
- **Risk Scoring**: Each link gets a risk score from 0-100%
- **History & Statistics**: Track all verified links with detailed reports
- **Whitelist/Blacklist**: Manage trusted and blocked domains

## Quick Start 🚀

### 1. Prerequisites

- Python 3.9 or higher
- pip (Python package manager)

### 2. Installation

```bash
# Clone or download the project
cd "AI Agent Link Verifier"

# Create a virtual environment (recommended)
python -m venv venv

# Activate virtual environment
# On Windows:
venv\Scripts\activate
# On macOS/Linux:
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 3. Configuration

Copy the example environment file and configure it:

```bash
copy .env.example .env
```

Edit `.env` with your settings:

```env
# Required for email monitoring (use Gmail App Password)
EMAIL_USERNAME=your-email@gmail.com
EMAIL_PASSWORD=your-app-password

# Optional: Enhanced scanning with external APIs
VIRUSTOTAL_API_KEY=your-api-key
GOOGLE_SAFE_BROWSING_API_KEY=your-api-key
```

**Gmail Setup**: If using Gmail, you need to create an App Password:
1. Go to [Google Account Security](https://myaccount.google.com/security)
2. Enable 2-Factor Authentication
3. Go to App Passwords
4. Create a new App Password for "Mail"
5. Use this password in your `.env` file

### 4. Run the Application

```bash
python app.py
```

Open your browser and go to: **http://localhost:5000**

## Usage 📖

### Manual Link Verification

1. Open the web interface at http://localhost:5000
2. Paste any URL into the input field
3. Click "Verify Link"
4. View the detailed security analysis

### Email Monitoring

1. Configure your email credentials in `.env`
2. Click "Check Emails Now" to scan recent emails
3. Or click "Start Monitoring" for continuous background scanning
4. You'll receive desktop notifications for dangerous links

### Understanding Results

| Risk Level | Score | Meaning |
|------------|-------|---------|
| 🟢 Safe | 0-20% | Link appears safe |
| 🔵 Low | 20-40% | Minor concerns, likely safe |
| 🟡 Medium | 40-70% | Proceed with caution |
| 🟠 High | 70-80% | Likely dangerous |
| 🔴 Critical | 80-100% | Do not click! |

## API Endpoints 🔌

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/verify` | POST | Verify a single URL |
| `/api/history` | GET | Get verification history |
| `/api/stats` | GET | Get statistics |
| `/api/check-emails` | POST | Check emails for links |
| `/api/email/start` | POST | Start email monitoring |
| `/api/email/stop` | POST | Stop email monitoring |
| `/api/whitelist` | GET/POST | Manage whitelist |
| `/api/blacklist` | GET/POST | Manage blacklist |

### Example API Usage

```python
import requests

# Verify a link
response = requests.post('http://localhost:5000/api/verify', 
    json={'url': 'https://example.com'})
result = response.json()
print(f"Safe: {result['is_safe']}, Risk: {result['risk_level']}")
```

## Project Structure 📁

```
AI Agent Link Verifier/
├── app.py              # Flask web application
├── link_verifier.py    # Core URL analysis engine
├── email_monitor.py    # Email monitoring service
├── notifications.py    # Desktop/email notifications
├── database.py         # SQLite database models
├── config.py           # Configuration management
├── requirements.txt    # Python dependencies
├── .env.example        # Example environment file
├── templates/
│   └── index.html      # Web interface
└── README.md           # This file
```

## Security Checks Performed 🔍

1. **URL Structure Analysis**
   - Detects IP addresses instead of domains
   - Identifies credential injection attempts (@ symbol)
   - Finds double-encoding tricks
   - Spots suspicious file extensions

2. **Domain Analysis**
   - Checks for suspicious TLDs (.tk, .ml, etc.)
   - Detects brand impersonation (paypa1.com, amaz0n.com)
   - Identifies typosquatting patterns
   - Analyzes subdomain structures

3. **Technical Checks**
   - SSL certificate validation
   - DNS resolution verification
   - Domain age via WHOIS
   - Redirect chain analysis

4. **External Services** (optional)
   - VirusTotal malware database
   - Google Safe Browsing

## Troubleshooting 🔧

### Email Connection Failed
- Verify your email credentials are correct
- For Gmail, ensure you're using an App Password
- Check if IMAP is enabled in your email settings

### Desktop Notifications Not Working
- On Windows, ensure Windows notifications are enabled
- Install the optional `win10toast` package
- Run the app with administrator privileges if needed

### Missing Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

## Contributing 🤝

Contributions are welcome! Please feel free to submit a Pull Request.

## License 📄

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer ⚠️

This tool provides security analysis based on heuristics and pattern matching. While it can detect many common threats, no tool can guarantee 100% accuracy. Always exercise caution with unfamiliar links.

---

Built with ❤️ for safer browsing
