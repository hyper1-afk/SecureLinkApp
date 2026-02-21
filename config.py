"""
Configuration settings for the SecureLink application.

Copyright (c) 2026 SecureLink. All rights reserved.
Unauthorized copying, modification, or distribution of this software is strictly prohibited.
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    """Application configuration"""
    
    # Flask settings
    SECRET_KEY = os.getenv('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("SECRET_KEY environment variable is required")
    
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    FLASK_ENV = os.getenv('FLASK_ENV', 'production')
    APP_URL = os.getenv('APP_URL', 'http://localhost:5000')
    
    # Database
    DATABASE_URL = os.getenv('DATABASE_URL')  # PostgreSQL for production
    DATABASE_PATH = os.getenv('DATABASE_PATH', 'link_verifier.db')  # SQLite fallback
    
    # Email Settings (IMAP)
    EMAIL_HOST = os.getenv('EMAIL_HOST', 'imap.gmail.com')
    EMAIL_PORT = int(os.getenv('EMAIL_PORT', 993))
    EMAIL_USERNAME = os.getenv('EMAIL_USERNAME', '')
    EMAIL_PASSWORD = os.getenv('EMAIL_PASSWORD', '')
    EMAIL_USE_SSL = os.getenv('EMAIL_USE_SSL', 'True').lower() == 'true'
    EMAIL_CHECK_INTERVAL = int(os.getenv('EMAIL_CHECK_INTERVAL', 60))
    
    # VirusTotal API (optional - for enhanced scanning)
    VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '')
    
    # Google Safe Browsing API (optional)
    GOOGLE_SAFE_BROWSING_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
    
    # Notification Settings
    ENABLE_DESKTOP_NOTIFICATIONS = os.getenv('ENABLE_DESKTOP_NOTIFICATIONS', 'False').lower() == 'true'
    ENABLE_EMAIL_NOTIFICATIONS = os.getenv('ENABLE_EMAIL_NOTIFICATIONS', 'True').lower() == 'true'
    NOTIFICATION_EMAIL = os.getenv('NOTIFICATION_EMAIL', '')
    
    # Support/Admin email for ticket notifications
    SUPPORT_EMAIL = os.getenv('SUPPORT_EMAIL', '')
    
    # Support Inbox Settings (IMAP - for auto-creating tickets from emails)
    SUPPORT_EMAIL_ADDRESS = os.getenv('SUPPORT_EMAIL_ADDRESS', '')  # e.g., support@securelinkapp.com
    SUPPORT_EMAIL_PASSWORD = os.getenv('SUPPORT_EMAIL_PASSWORD', '')
    SUPPORT_IMAP_HOST = os.getenv('SUPPORT_IMAP_HOST', 'imap.secureserver.net')  # GoDaddy default
    SUPPORT_IMAP_PORT = int(os.getenv('SUPPORT_IMAP_PORT', 993))
    SUPPORT_IMAP_SSL = os.getenv('SUPPORT_IMAP_SSL', 'True').lower() == 'true'
    SUPPORT_EMAIL_CHECK_INTERVAL = int(os.getenv('SUPPORT_EMAIL_CHECK_INTERVAL', 60))  # seconds
    
    # SMTP Settings for outgoing emails (AWS SES)
    SMTP_HOST = os.getenv('SMTP_HOST', 'email-smtp.us-east-2.amazonaws.com')
    SMTP_PORT = int(os.getenv('SMTP_PORT', 587))
    SMTP_USERNAME = os.getenv('SMTP_USERNAME', '')
    SMTP_PASSWORD = os.getenv('SMTP_PASSWORD', '')
    SMTP_FROM_EMAIL = os.getenv('SMTP_FROM_EMAIL', 'support@securelinkapp.com')
    SMTP_USE_TLS = os.getenv('SMTP_USE_TLS', 'True').lower() == 'true'
    SMTP_USE_SSL = os.getenv('SMTP_USE_SSL', 'False').lower() == 'true'  # For port 465
    
    # Risk Thresholds
    HIGH_RISK_THRESHOLD = float(os.getenv('HIGH_RISK_THRESHOLD', 0.7))
    MEDIUM_RISK_THRESHOLD = float(os.getenv('MEDIUM_RISK_THRESHOLD', 0.4))
    
    # URL Analysis Settings
    ENABLE_DNS_CHECK = os.getenv('ENABLE_DNS_CHECK', 'True').lower() == 'true'
    ENABLE_WHOIS_CHECK = os.getenv('ENABLE_WHOIS_CHECK', 'True').lower() == 'true'
    ENABLE_SSL_CHECK = os.getenv('ENABLE_SSL_CHECK', 'True').lower() == 'true'
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', 10))
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'link_verifier.log')
    
    # Stripe Payment Settings - REQUIRED for payments
    STRIPE_SECRET_KEY = os.getenv('STRIPE_SECRET_KEY')
    STRIPE_PUBLISHABLE_KEY = os.getenv('STRIPE_PUBLISHABLE_KEY')
    STRIPE_WEBHOOK_SECRET = os.getenv('STRIPE_WEBHOOK_SECRET', '')
    
    # Stripe Price IDs
    STRIPE_PRO_MONTHLY_PRICE_ID = os.getenv('STRIPE_PRO_MONTHLY_PRICE_ID', '')
    STRIPE_PRO_YEARLY_PRICE_ID = os.getenv('STRIPE_PRO_YEARLY_PRICE_ID', '')
    STRIPE_ENTERPRISE_MONTHLY_PRICE_ID = os.getenv('STRIPE_ENTERPRISE_MONTHLY_PRICE_ID', '')
    STRIPE_ENTERPRISE_YEARLY_PRICE_ID = os.getenv('STRIPE_ENTERPRISE_YEARLY_PRICE_ID', '')
    
    # OAuth Settings (Social Login) - REQUIRED for OAuth
    GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
    
    # Microsoft OAuth (optional)
    MICROSOFT_CLIENT_ID = os.getenv('MICROSOFT_CLIENT_ID', '')
    MICROSOFT_CLIENT_SECRET = os.getenv('MICROSOFT_CLIENT_SECRET', '')
    
    # Yahoo OAuth (optional)
    YAHOO_CLIENT_ID = os.getenv('YAHOO_CLIENT_ID', '')
    YAHOO_CLIENT_SECRET = os.getenv('YAHOO_CLIENT_SECRET', '')
    
    # NewsAPI for Security News Feed
    NEWS_API_KEY = os.getenv('NEWS_API_KEY', '')
    
    # Have I Been Pwned API Key (for Dark Web Monitoring)
    HIBP_API_KEY = os.getenv('HIBP_API_KEY', '')


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
