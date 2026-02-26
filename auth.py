"""
User Authentication and Session Management
Handles user registration, login, persistent sessions, and subscriptions.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
import os
import hashlib
import secrets
import smtplib
import bcrypt
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

from config import Config

import logging
logger = logging.getLogger(__name__)

Base = declarative_base()


class SubscriptionTier(Enum):
    """Subscription plans"""
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"


class User(Base):
    """User account model"""
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    username = Column(String(100), unique=True, nullable=False, index=True)
    password_hash = Column(String(256), nullable=True)  # Nullable for OAuth users
    salt = Column(String(64), nullable=True)  # Nullable for OAuth users
    
    # Profile info
    full_name = Column(String(200), nullable=True)
    avatar_url = Column(String(500), nullable=True)
    
    # OAuth info
    oauth_provider = Column(String(50), nullable=True)  # google, microsoft, yahoo
    oauth_provider_id = Column(String(255), nullable=True)  # Provider's user ID
    
    # Subscription
    subscription_tier = Column(String(20), default=SubscriptionTier.FREE.value)
    subscription_expires = Column(DateTime, nullable=True)
    stripe_customer_id = Column(String(100), nullable=True)
    stripe_subscription_id = Column(String(100), nullable=True)
    
    # Dark web monitoring
    dark_web_monitoring_enabled = Column(Boolean, default=False)
    dark_web_last_scan = Column(DateTime, nullable=True)
    dark_web_alert_email = Column(Boolean, default=True)  # Send email on new findings
    
    # Notification preferences
    desktop_notifications = Column(Boolean, default=True)
    email_notifications = Column(Boolean, default=False)
    notification_email = Column(String(255), nullable=True)
    weekly_reports_enabled = Column(Boolean, default=True)  # Weekly security reports
    
    # Account status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    verification_token = Column(String(100), nullable=True)
    tutorial_seen = Column(Boolean, default=False)  # Track if user has seen the tutorial
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)
    
    # Relationships
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")
    email_accounts = relationship("EmailAccount", back_populates="user", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'email': self.email,
            'username': self.username,
            'full_name': self.full_name,
            'avatar_url': self.avatar_url,
            'oauth_provider': getattr(self, 'oauth_provider', None),
            'subscription_tier': self.subscription_tier,
            'subscription_expires': self.subscription_expires.isoformat() if self.subscription_expires else None,
            'stripe_customer_id': getattr(self, 'stripe_customer_id', None),
            'stripe_subscription_id': getattr(self, 'stripe_subscription_id', None),
            'dark_web_monitoring_enabled': getattr(self, 'dark_web_monitoring_enabled', False),
            'dark_web_last_scan': self.dark_web_last_scan.isoformat() if getattr(self, 'dark_web_last_scan', None) else None,
            'desktop_notifications': self.desktop_notifications,
            'email_notifications': self.email_notifications,
            'weekly_reports_enabled': getattr(self, 'weekly_reports_enabled', True),
            'is_verified': self.is_verified,
            'tutorial_seen': getattr(self, 'tutorial_seen', False),
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None
        }
    
    def get_plan_limits(self) -> Dict:
        """Get feature limits based on subscription tier"""
        limits = {
            SubscriptionTier.FREE.value: {
                'daily_scans': 25,
                'dark_web_monitoring': False,
                'max_monitored_assets': 0,
                'api_access': False,
                'priority_support': False,
                'advanced_analysis': False,
                'whitelist_blacklist': False,
                'export_reports': False,
                'max_monitored_domains': 0,
                'scan_frequency': None,
                'ai_remediation': False,
                'attack_surface': False,
            },
            SubscriptionTier.PRO.value: {
                'daily_scans': -1,  # Unlimited
                'dark_web_monitoring': True,
                'max_monitored_assets': 5,
                'api_access': True,
                'priority_support': False,
                'advanced_analysis': True,
                'whitelist_blacklist': True,
                'export_reports': True,
                'max_monitored_domains': 0,
                'scan_frequency': None,
                'ai_remediation': False,
                'attack_surface': False,
            },
            SubscriptionTier.ENTERPRISE.value: {
                'daily_scans': -1,  # Unlimited
                'dark_web_monitoring': True,
                'max_monitored_assets': -1,  # Unlimited
                'api_access': True,
                'priority_support': True,
                'advanced_analysis': True,
                'whitelist_blacklist': True,
                'export_reports': True,
                'max_monitored_domains': 25,
                'scan_frequency': 'hourly',
                'ai_remediation': True,
                'attack_surface': True,
            }
        }
        return limits.get(self.subscription_tier, limits[SubscriptionTier.FREE.value])


class UserSession(Base):
    """Persistent session tokens for remember-me functionality"""
    __tablename__ = 'user_sessions'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String(256), unique=True, nullable=False, index=True)
    device_info = Column(String(500), nullable=True)
    ip_address = Column(String(45), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    last_used = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    
    user = relationship("User", back_populates="sessions")


class EmailAccount(Base):
    """Multiple email accounts for monitoring"""
    __tablename__ = 'email_accounts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    # Email configuration
    email = Column(String(255), nullable=False)
    host = Column(String(255), nullable=False, default='imap.gmail.com')
    port = Column(Integer, default=993)
    password_encrypted = Column(Text, nullable=True)
    
    # Status
    is_active = Column(Boolean, default=True)
    is_verified = Column(Boolean, default=False)
    last_checked = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    
    # Settings
    check_frequency = Column(Integer, default=5)  # minutes
    label = Column(String(100), nullable=True)  # nickname like "Work Email"
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationship
    user = relationship("User", back_populates="email_accounts")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'email': self.email,
            'host': self.host,
            'port': self.port,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'last_checked': self.last_checked.isoformat() if self.last_checked else None,
            'last_error': self.last_error,
            'check_frequency': self.check_frequency,
            'label': self.label or self.email,
            'has_password': bool(self.password_encrypted),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class DailyScanCount(Base):
    """Track daily scan usage per user"""
    __tablename__ = 'daily_scan_counts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    date = Column(DateTime, nullable=False)
    count = Column(Integer, default=0)


class MonitoredAsset(Base):
    """Assets being monitored on the dark web (emails, domains, usernames, phones)"""
    __tablename__ = 'monitored_assets'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    
    asset_type = Column(String(20), nullable=False)  # email, domain, username, phone
    asset_value = Column(String(255), nullable=False)
    label = Column(String(100), nullable=True)  # User-friendly label
    
    # Monitoring status
    is_active = Column(Boolean, default=True)
    last_scanned = Column(DateTime, nullable=True)
    last_error = Column(Text, nullable=True)
    
    # Results cache
    breach_count = Column(Integer, default=0)
    paste_count = Column(Integer, default=0)
    risk_level = Column(String(20), default='unknown')  # safe, low, medium, high, critical
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = relationship("User", backref="monitored_assets")
    alerts = relationship("DarkWebAlert", back_populates="asset", cascade="all, delete-orphan")
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'asset_type': self.asset_type,
            'asset_value': self.asset_value,
            'label': self.label or self.asset_value,
            'is_active': self.is_active,
            'last_scanned': self.last_scanned.isoformat() if self.last_scanned else None,
            'last_error': self.last_error,
            'breach_count': self.breach_count,
            'paste_count': self.paste_count,
            'risk_level': self.risk_level,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class DarkWebAlert(Base):
    """Individual dark web findings/alerts"""
    __tablename__ = 'dark_web_alerts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    asset_id = Column(Integer, ForeignKey('monitored_assets.id'), nullable=False)
    
    # Alert details
    alert_type = Column(String(50), nullable=False)  # data_breach, paste_exposure, credential_leak
    severity = Column(String(20), nullable=False)  # critical, high, medium, low, info
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    source = Column(String(100), nullable=True)  # e.g., "Have I Been Pwned"
    source_ref = Column(String(255), nullable=True)  # e.g., breach name
    
    # Breach details
    breach_date = Column(DateTime, nullable=True)
    exposed_records = Column(Integer, default=0)
    exposed_data_types = Column(Text, nullable=True)  # JSON array of data types
    
    # Status
    is_read = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)
    resolved_at = Column(DateTime, nullable=True)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # Relationships
    asset = relationship("MonitoredAsset", back_populates="alerts")
    
    def to_dict(self) -> Dict:
        import json
        data_types = []
        if self.exposed_data_types:
            try:
                data_types = json.loads(self.exposed_data_types)
            except:
                data_types = [self.exposed_data_types]
        
        return {
            'id': self.id,
            'asset_id': self.asset_id,
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'description': self.description,
            'source': self.source,
            'source_ref': self.source_ref,
            'breach_date': self.breach_date.isoformat() if self.breach_date else None,
            'exposed_records': self.exposed_records,
            'exposed_data_types': data_types,
            'is_read': self.is_read,
            'is_resolved': self.is_resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class PasswordResetToken(Base):
    """Password reset tokens"""
    __tablename__ = 'password_reset_tokens'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey('users.id'), nullable=False)
    token_hash = Column(String(256), unique=True, nullable=False, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=False)
    used = Column(Boolean, default=False)
    
    user = relationship("User")


class AuthManager:
    """Handles user authentication and session management"""
    
    # Session duration for "remember me" - 30 days
    REMEMBER_ME_DURATION = timedelta(days=30)
    # Regular session duration - 24 hours
    SESSION_DURATION = timedelta(hours=24)
    # Inactivity timeout - 30 minutes
    INACTIVITY_TIMEOUT = timedelta(minutes=30)
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        
        # Use shared database engine
        from db_engine import get_database_engine, safe_create_tables
        self.engine = get_database_engine(self.config)
        
        # Only create tables if they don't exist (safe for production)
        safe_create_tables(Base.metadata, self.engine)
        self._migrate_database()
        self.Session = sessionmaker(bind=self.engine)
    
    def _migrate_database(self):
        """Add new columns if they don't exist (simple migration)"""
        from sqlalchemy import inspect, text
        inspector = inspect(self.engine)
        
        if 'users' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('users')]
            
            with self.engine.connect() as conn:
                if 'weekly_reports_enabled' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN weekly_reports_enabled BOOLEAN DEFAULT TRUE'))
                    conn.commit()
                
                if 'stripe_subscription_id' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN stripe_subscription_id VARCHAR(100)'))
                    conn.commit()
                    
                if 'stripe_customer_id' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN stripe_customer_id VARCHAR(100)'))
                    conn.commit()
                
                # OAuth columns
                if 'oauth_provider' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN oauth_provider VARCHAR(50)'))
                    conn.commit()
                
                if 'oauth_provider_id' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN oauth_provider_id VARCHAR(255)'))
                    conn.commit()
                
                # Tutorial tracking
                if 'tutorial_seen' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN tutorial_seen BOOLEAN DEFAULT FALSE'))
                    conn.commit()
                
                # Dark web monitoring columns
                if 'dark_web_monitoring_enabled' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN dark_web_monitoring_enabled BOOLEAN DEFAULT FALSE'))
                    conn.commit()
                if 'dark_web_last_scan' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN dark_web_last_scan TIMESTAMP'))
                    conn.commit()
                if 'dark_web_alert_email' not in columns:
                    conn.execute(text('ALTER TABLE users ADD COLUMN dark_web_alert_email BOOLEAN DEFAULT TRUE'))
                    conn.commit()
    
    def get_session(self):
        return self.Session()
    
    def _hash_password(self, password: str, salt: str = None) -> str:
        """Hash password using bcrypt (salt is embedded in the hash).
        The `salt` parameter is kept for API compatibility but ignored by bcrypt.
        Bcrypt generates and embeds its own salt in the output hash."""
        pw_bytes = password.encode('utf-8')
        hashed = bcrypt.hashpw(pw_bytes, bcrypt.gensalt(rounds=12))
        return hashed.decode('utf-8')

    def _verify_password(self, password: str, stored_hash: str, legacy_salt: str = None) -> bool:
        """Verify a password against a stored hash.
        Supports both bcrypt hashes (start with $2b$) and legacy SHA-256 hashes."""
        if stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'):
            # Modern bcrypt hash
            return bcrypt.checkpw(password.encode('utf-8'), stored_hash.encode('utf-8'))
        else:
            # Legacy SHA-256 hash — verify then caller should upgrade
            if legacy_salt:
                legacy_hash = hashlib.sha256((password + legacy_salt).encode()).hexdigest()
                return legacy_hash == stored_hash
            return False

    def _needs_rehash(self, stored_hash: str) -> bool:
        """Check if a password hash needs to be upgraded from SHA-256 to bcrypt."""
        return not (stored_hash.startswith('$2b$') or stored_hash.startswith('$2a$'))
    
    def _generate_salt(self) -> str:
        """Generate a random salt"""
        return secrets.token_hex(32)
    
    def _generate_token(self) -> str:
        """Generate a secure session token"""
        return secrets.token_urlsafe(64)
    
    def _hash_token(self, token: str) -> str:
        """Hash a session token"""
        return hashlib.sha256(token.encode()).hexdigest()
    
    def _send_verification_email(self, email: str, username: str, token: str, base_url: str = None) -> bool:
        """Send email verification link to user"""
        try:
            if not base_url:
                base_url = 'https://securelinkapp.com'
            
            verification_url = f"{base_url}/verify-email?token={token}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 40px; }}
                    .logo {{ text-align: center; margin-bottom: 30px; }}
                    .logo h1 {{ color: #0ea5e9; margin: 0; font-size: 28px; }}
                    h2 {{ color: #f8fafc; margin-top: 0; }}
                    p {{ color: #cbd5e1; line-height: 1.6; }}
                    .btn {{ display: inline-block; background: linear-gradient(135deg, #0ea5e9, #0284c7); color: white; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 600; margin: 20px 0; }}
                    .btn:hover {{ background: linear-gradient(135deg, #0284c7, #0369a1); }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #334155; color: #94a3b8; font-size: 13px; text-align: center; }}
                    .link {{ color: #0ea5e9; word-break: break-all; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo">
                        <h1>🔒 SecureLink</h1>
                    </div>
                    <h2>Verify Your Email Address</h2>
                    <p>Hi {username},</p>
                    <p>Thanks for signing up for SecureLink! Please verify your email address by clicking the button below:</p>
                    <p style="text-align: center;">
                        <a href="{verification_url}" class="btn">Verify Email Address</a>
                    </p>
                    <p>Or copy and paste this link into your browser:</p>
                    <p class="link">{verification_url}</p>
                    <p>This link will expire in 24 hours.</p>
                    <p>If you didn't create a SecureLink account, you can safely ignore this email.</p>
                    <div class="footer">
                        <p>© 2026 SecureLink. All rights reserved.</p>
                        <p>Protecting you from malicious links, one click at a time.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            Verify Your Email Address
            
            Hi {username},
            
            Thanks for signing up for SecureLink! Please verify your email address by clicking the link below:
            
            {verification_url}
            
            This link will expire in 24 hours.
            
            If you didn't create a SecureLink account, you can safely ignore this email.
            
            © 2026 SecureLink
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Verify your SecureLink email address'
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', None) or self.config.SMTP_USERNAME or 'support@securelinkapp.com'
            msg['To'] = email
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            smtp_host = self.config.SMTP_HOST or 'email-smtp.us-east-2.amazonaws.com'
            smtp_port = self.config.SMTP_PORT or 587
            smtp_user = self.config.SMTP_USERNAME or self.config.EMAIL_USERNAME
            smtp_pass = self.config.SMTP_PASSWORD or self.config.EMAIL_PASSWORD
            
            if not smtp_user or not smtp_pass:
                print("Warning: SMTP not configured - verification email not sent")
                return False
            
            if getattr(self.config, 'SMTP_USE_SSL', False) or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            
            return True
            
        except Exception as e:
            print(f"Failed to send verification email: {e}")
            return False
    
    def _send_welcome_email(self, email: str, username: str, full_name: Optional[str] = None) -> bool:
        """Send a welcome email after a user successfully verifies their account"""
        try:
            display_name = full_name or username
            login_url = 'https://securelinkapp.com/login'

            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 40px; }}
                    .logo {{ text-align: center; margin-bottom: 30px; }}
                    .logo h1 {{ color: #0ea5e9; margin: 0; font-size: 28px; }}
                    h2 {{ color: #f8fafc; margin-top: 0; }}
                    p {{ color: #cbd5e1; line-height: 1.6; }}
                    .btn {{ display: inline-block; background: linear-gradient(135deg, #0ea5e9, #0284c7); color: white; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 600; margin: 20px 0; }}
                    .features {{ background: #0f172a; border-radius: 12px; padding: 24px; margin: 24px 0; }}
                    .feature {{ display: flex; align-items: flex-start; margin-bottom: 16px; }}
                    .feature:last-child {{ margin-bottom: 0; }}
                    .feature-icon {{ font-size: 20px; margin-right: 14px; flex-shrink: 0; }}
                    .feature-text {{ color: #cbd5e1; }}
                    .feature-text strong {{ color: #f8fafc; display: block; margin-bottom: 2px; }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #334155; color: #94a3b8; font-size: 13px; text-align: center; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo">
                        <h1>&#128274; SecureLink</h1>
                    </div>
                    <h2>Welcome to SecureLink, {display_name}!</h2>
                    <p>Your account is verified and ready to go. We're glad to have you.</p>
                    <p>Here's what you can do right away:</p>
                    <div class="features">
                        <div class="feature">
                            <span class="feature-icon">&#128269;</span>
                            <div class="feature-text">
                                <strong>Link &amp; Website Scanner</strong>
                                Instantly check any URL for malware, phishing, and suspicious activity before you click.
                            </div>
                        </div>
                        <div class="feature">
                            <span class="feature-icon">&#128737;</span>
                            <div class="feature-text">
                                <strong>Security Dashboard</strong>
                                Monitor your overall security posture and get a real-time snapshot of threats and alerts.
                            </div>
                        </div>
                        <div class="feature">
                            <span class="feature-icon">&#128202;</span>
                            <div class="feature-text">
                                <strong>Threat Intelligence</strong>
                                Stay informed with live threat feeds and dark web monitoring to protect your data.
                            </div>
                        </div>
                    </div>
                    <p style="text-align: center;">
                        <a href="{login_url}" class="btn">Go to Your Dashboard</a>
                    </p>
                    <p>If you have any questions, just reply to this email — we're happy to help.</p>
                    <div class="footer">
                        <p>&#169; 2026 SecureLink &mdash; securelinkapp.com</p>
                        <p>Protecting you from malicious links, one click at a time.</p>
                        <p>You're receiving this because you created a SecureLink account.</p>
                    </div>
                </div>
            </body>
            </html>
            """

            text_content = f"""
Welcome to SecureLink, {display_name}!

Your account is verified and ready to go.

Here's what you can do right away:

- Link & Website Scanner: Check any URL for malware and phishing instantly.
- Security Dashboard: Monitor your security posture in real time.
- Threat Intelligence: Live threat feeds and dark web monitoring.

Log in and get started: {login_url}

If you have any questions, just reply to this email.

© 2026 SecureLink — securelinkapp.com
            """

            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Welcome to SecureLink!'
            msg['From'] = 'SecureLink <welcome@securelinkapp.com>'
            msg['To'] = email

            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))

            smtp_host = self.config.SMTP_HOST or 'email-smtp.us-east-2.amazonaws.com'
            smtp_port = self.config.SMTP_PORT or 587
            smtp_user = self.config.SMTP_USERNAME or self.config.EMAIL_USERNAME
            smtp_pass = self.config.SMTP_PASSWORD or self.config.EMAIL_PASSWORD

            if not smtp_user or not smtp_pass:
                logger.warning("SMTP not configured — welcome email not sent")
                return False

            if getattr(self.config, 'SMTP_USE_SSL', False) or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)

            logger.info(f"Welcome email sent to {email}")
            return True

        except Exception as e:
            logger.error(f"Failed to send welcome email to {email}: {e}")
            return False

    def request_password_reset(self, email: str, base_url: str = None) -> Dict:
        """Request a password reset - sends email with reset link"""
        session = self.get_session()
        try:
            # Find user by email
            user = session.query(User).filter(User.email == email).first()
            
            if not user:
                # Don't reveal if email exists - security best practice
                return {'success': True, 'message': 'If that email exists, a reset link has been sent.'}
            
            # Generate reset token
            token = secrets.token_urlsafe(32)
            token_hash = self._hash_token(token)
            
            # Delete any existing reset tokens for this user
            session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user.id).delete()
            
            # Create new reset token (expires in 1 hour)
            reset_token = PasswordResetToken(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=datetime.utcnow() + timedelta(hours=1)
            )
            session.add(reset_token)
            session.commit()
            
            # Send reset email
            self._send_password_reset_email(user.email, user.username, token, base_url)
            
            return {'success': True, 'message': 'If that email exists, a reset link has been sent.'}
            
        except Exception as e:
            session.rollback()
            print(f"Password reset request error: {e}")
            return {'success': False, 'error': 'Failed to process reset request'}
        finally:
            session.close()
    
    def _send_password_reset_email(self, email: str, username: str, token: str, base_url: str = None) -> bool:
        """Send password reset email"""
        try:
            if not base_url:
                base_url = 'https://securelinkapp.com'
            
            reset_url = f"{base_url}/reset-password?token={token}"
            
            html_content = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <meta charset="UTF-8">
                <style>
                    body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #0f172a; color: #f8fafc; margin: 0; padding: 40px 20px; }}
                    .container {{ max-width: 600px; margin: 0 auto; background: #1e293b; border-radius: 16px; padding: 40px; }}
                    .logo {{ text-align: center; margin-bottom: 30px; }}
                    .logo h1 {{ color: #0ea5e9; margin: 0; font-size: 28px; }}
                    h2 {{ color: #f8fafc; margin-top: 0; }}
                    p {{ color: #cbd5e1; line-height: 1.6; }}
                    .btn {{ display: inline-block; background: linear-gradient(135deg, #ef4444, #dc2626); color: white; text-decoration: none; padding: 14px 32px; border-radius: 10px; font-weight: 600; margin: 20px 0; }}
                    .btn:hover {{ background: linear-gradient(135deg, #dc2626, #b91c1c); }}
                    .footer {{ margin-top: 30px; padding-top: 20px; border-top: 1px solid #334155; color: #94a3b8; font-size: 13px; text-align: center; }}
                    .link {{ color: #0ea5e9; word-break: break-all; }}
                    .warning {{ background: #fef3c7; color: #92400e; padding: 12px 16px; border-radius: 8px; margin: 20px 0; }}
                </style>
            </head>
            <body>
                <div class="container">
                    <div class="logo">
                        <h1>🔒 SecureLink</h1>
                    </div>
                    <h2>Reset Your Password</h2>
                    <p>Hi {username},</p>
                    <p>We received a request to reset your password. Click the button below to create a new password:</p>
                    <p style="text-align: center;">
                        <a href="{reset_url}" class="btn">Reset Password</a>
                    </p>
                    <p>Or copy and paste this link into your browser:</p>
                    <p class="link">{reset_url}</p>
                    <div class="warning">
                        ⚠️ This link will expire in 1 hour for security reasons.
                    </div>
                    <p>If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.</p>
                    <div class="footer">
                        <p>© 2026 SecureLink. All rights reserved.</p>
                        <p>Protecting you from malicious links, one click at a time.</p>
                    </div>
                </div>
            </body>
            </html>
            """
            
            text_content = f"""
            Reset Your Password
            
            Hi {username},
            
            We received a request to reset your password. Click the link below to create a new password:
            
            {reset_url}
            
            This link will expire in 1 hour for security reasons.
            
            If you didn't request a password reset, you can safely ignore this email. Your password will remain unchanged.
            
            © 2026 SecureLink
            """
            
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'Reset your SecureLink password'
            msg['From'] = getattr(self.config, 'SMTP_FROM_EMAIL', None) or self.config.SMTP_USERNAME or 'support@securelinkapp.com'
            msg['To'] = email
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            smtp_host = self.config.SMTP_HOST or 'email-smtp.us-east-2.amazonaws.com'
            smtp_port = self.config.SMTP_PORT or 587
            smtp_user = self.config.SMTP_USERNAME or self.config.EMAIL_USERNAME
            smtp_pass = self.config.SMTP_PASSWORD or self.config.EMAIL_PASSWORD
            
            if not smtp_user or not smtp_pass:
                print("Warning: SMTP not configured - password reset email not sent")
                return False
            
            if getattr(self.config, 'SMTP_USE_SSL', False) or smtp_port == 465:
                with smtplib.SMTP_SSL(smtp_host, smtp_port) as server:
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            else:
                with smtplib.SMTP(smtp_host, smtp_port) as server:
                    server.starttls()
                    server.login(smtp_user, smtp_pass)
                    server.send_message(msg)
            
            print(f"Password reset email sent to {email}")
            return True
            
        except Exception as e:
            print(f"Failed to send password reset email: {e}")
            return False
    
    def verify_password_reset_token(self, token: str) -> Dict:
        """Verify a password reset token is valid"""
        session = self.get_session()
        try:
            token_hash = self._hash_token(token)
            
            reset_token = session.query(PasswordResetToken).filter(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.utcnow()
            ).first()
            
            if not reset_token:
                return {'valid': False, 'error': 'Invalid or expired reset link'}
            
            user = session.query(User).filter(User.id == reset_token.user_id).first()
            
            return {
                'valid': True,
                'email': user.email if user else None
            }
            
        except Exception as e:
            print(f"Token verification error: {e}")
            return {'valid': False, 'error': 'Failed to verify token'}
        finally:
            session.close()
    
    def reset_password_with_token(self, token: str, new_password: str) -> Dict:
        """Reset password using a valid reset token"""
        session = self.get_session()
        try:
            # Validate password strength
            if len(new_password) < 8:
                return {'success': False, 'error': 'Password must be at least 8 characters'}
            
            token_hash = self._hash_token(token)
            
            reset_token = session.query(PasswordResetToken).filter(
                PasswordResetToken.token_hash == token_hash,
                PasswordResetToken.used == False,
                PasswordResetToken.expires_at > datetime.utcnow()
            ).first()
            
            if not reset_token:
                return {'success': False, 'error': 'Invalid or expired reset link'}
            
            # Get user
            user = session.query(User).filter(User.id == reset_token.user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Update password with bcrypt
            password_hash = self._hash_password(new_password)
            
            user.password_hash = password_hash
            user.salt = 'bcrypt'
            
            # Mark token as used
            reset_token.used = True
            
            # Invalidate all existing sessions for security
            session.query(UserSession).filter(UserSession.user_id == user.id).delete()
            
            session.commit()
            
            return {'success': True, 'message': 'Password reset successfully. Please log in with your new password.'}
            
        except Exception as e:
            session.rollback()
            print(f"Password reset error: {e}")
            return {'success': False, 'error': 'Failed to reset password'}
        finally:
            session.close()

    def register(self, email: str, username: str, password: str, full_name: str = None) -> Dict:
        """Register a new user"""
        session = self.get_session()
        try:
            # Check if email or username exists
            existing = session.query(User).filter(
                (User.email == email) | (User.username == username)
            ).first()
            
            if existing:
                if existing.email == email:
                    return {'success': False, 'error': 'Email already registered'}
                return {'success': False, 'error': 'Username already taken'}
            
            # Create user with bcrypt password hash
            password_hash = self._hash_password(password)
            
            user = User(
                email=email,
                username=username,
                password_hash=password_hash,
                salt='bcrypt',
                full_name=full_name,
                verification_token=secrets.token_urlsafe(32)
            )
            
            session.add(user)
            session.commit()
            
            return {
                'success': True,
                'user': user.to_dict(),
                'verification_token': user.verification_token,
                'message': 'Account created successfully. Please verify your email.'
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def verify_email(self, token: str) -> Dict:
        """Verify a user's email address using the verification token"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.verification_token == token).first()
            
            if not user:
                return {'success': False, 'error': 'Invalid or expired verification link'}
            
            if user.is_verified:
                return {'success': True, 'message': 'Email already verified', 'already_verified': True}
            
            user.is_verified = True
            user.verification_token = None  # Clear the token after use
            user_email = str(user.email)
            user_username = str(user.username)
            user_full_name = str(user.full_name) if user.full_name is not None else None
            session.commit()

            # Send welcome email now that the account is confirmed
            self._send_welcome_email(user_email, user_username, user_full_name)

            return {
                'success': True,
                'message': 'Email verified successfully! You can now log in.',
                'user': user.to_dict()
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def resend_verification(self, email: str, base_url: str = None) -> Dict:
        """Resend verification email"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            
            if not user:
                # Don't reveal if email exists or not for security
                return {'success': True, 'message': 'If this email is registered, a verification link has been sent.'}
            
            if user.is_verified:
                return {'success': False, 'error': 'This email is already verified. Please log in.'}
            
            # Generate new verification token
            user.verification_token = secrets.token_urlsafe(32)
            session.commit()
            
            # Send the email
            self._send_verification_email(user.email, user.username, user.verification_token, base_url)
            
            return {'success': True, 'message': 'Verification email sent! Please check your inbox.'}
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def login(self, email_or_username: str, password: str, remember_me: bool = False,
              device_info: str = None, ip_address: str = None) -> Dict:
        """Authenticate user and create session"""
        session = self.get_session()
        try:
            # Find user (case-insensitive for email/username)
            from sqlalchemy import func
            email_or_username_lower = email_or_username.lower()
            user = session.query(User).filter(
                (func.lower(User.email) == email_or_username_lower) | 
                (func.lower(User.username) == email_or_username_lower)
            ).first()
            
            if not user:
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Verify password using bcrypt (with legacy SHA-256 fallback)
            if not self._verify_password(password, user.password_hash, user.salt):
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Transparently upgrade legacy SHA-256 hashes to bcrypt on successful login
            if self._needs_rehash(user.password_hash):
                user.password_hash = self._hash_password(password)
                user.salt = 'bcrypt'  # Mark as bcrypt-managed
                session.commit()
            
            if not user.is_active:
                return {'success': False, 'error': 'Account is deactivated'}
            
            # Check if email is verified
            # Skip verification for OAuth users and users created before verification was added
            # (users without a verification_token were created before this feature)
            if not user.is_verified and user.oauth_provider is None:
                # Auto-verify users who registered before email verification was implemented
                # These users have null verification_token or were created before Feb 5, 2026
                if user.verification_token is None or (user.created_at and user.created_at < datetime(2026, 2, 5)):
                    user.is_verified = True
                    session.commit()
                else:
                    return {
                        'success': False, 
                        'error': 'Please verify your email before logging in. Check your inbox for the verification link.',
                        'email_not_verified': True,
                        'email': user.email
                    }
            
            # Update last login
            user.last_login = datetime.utcnow()
            
            # Create session token
            token = self._generate_token()
            token_hash = self._hash_token(token)
            
            duration = self.REMEMBER_ME_DURATION if remember_me else self.SESSION_DURATION
            
            user_session = UserSession(
                user_id=user.id,
                token_hash=token_hash,
                device_info=device_info,
                ip_address=ip_address,
                expires_at=datetime.utcnow() + duration
            )
            
            session.add(user_session)
            session.commit()
            
            return {
                'success': True,
                'user': user.to_dict(),
                'token': token,
                'expires_at': user_session.expires_at.isoformat(),
                'plan_limits': user.get_plan_limits()
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate a session token and return user info.
        Sessions are invalidated after 30 minutes of inactivity."""
        session = self.get_session()
        try:
            token_hash = self._hash_token(token)
            
            user_session = session.query(UserSession).filter(
                UserSession.token_hash == token_hash,
                UserSession.is_active == True,
                UserSession.expires_at > datetime.utcnow()
            ).first()
            
            if not user_session:
                return None
            
            # Enforce inactivity timeout — expire session if idle > 30 minutes
            if user_session.last_used and \
               (datetime.utcnow() - user_session.last_used) > self.INACTIVITY_TIMEOUT:
                user_session.is_active = False
                session.commit()
                return None
            
            # Update last used
            user_session.last_used = datetime.utcnow()
            session.commit()
            
            user = user_session.user
            return {
                'user': user.to_dict(),
                'plan_limits': user.get_plan_limits()
            }
            
        except Exception as e:
            return None
        finally:
            session.close()
    
    def logout(self, token: str) -> bool:
        """Invalidate a session token"""
        session = self.get_session()
        try:
            token_hash = self._hash_token(token)
            
            user_session = session.query(UserSession).filter(
                UserSession.token_hash == token_hash
            ).first()
            
            if user_session:
                user_session.is_active = False
                session.commit()
                return True
            
            return False
            
        except Exception as e:
            return False
        finally:
            session.close()
    
    def reset_password_by_email(self, email: str, new_password: str) -> Dict:
        """Reset password for a user by email (admin function)"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Hash with bcrypt
            password_hash = self._hash_password(new_password)
            
            user.salt = 'bcrypt'
            user.password_hash = password_hash
            session.commit()
            
            return {'success': True, 'message': f'Password reset for {email}'}
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def reset_password_by_username(self, username: str, new_password: str) -> Dict:
        """Reset password for a user by username (admin function)"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.username == username).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Hash with bcrypt
            password_hash = self._hash_password(new_password)
            
            user.salt = 'bcrypt'
            user.password_hash = password_hash
            session.commit()
            
            return {'success': True, 'message': f'Password reset for {username}'}
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()

    def logout_all_devices(self, user_id: int) -> bool:
        """Logout from all devices"""
        session = self.get_session()
        try:
            session.query(UserSession).filter(
                UserSession.user_id == user_id
            ).update({'is_active': False})
            session.commit()
            return True
        except Exception as e:
            return False
        finally:
            session.close()
    
    def delete_user(self, user_id: int) -> Dict:
        """Permanently delete a user and all their data"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            username = user.username
            email = user.email
            
            # Delete all related records to avoid foreign key violations
            session.query(DailyScanCount).filter(DailyScanCount.user_id == user_id).delete()
            session.query(PasswordResetToken).filter(PasswordResetToken.user_id == user_id).delete()
            session.query(UserSession).filter(UserSession.user_id == user_id).delete()
            session.query(EmailAccount).filter(EmailAccount.user_id == user_id).delete()
            
            # Delete community/forum data (no FK constraints but clean up anyway)
            from database import (VerificationRecord, CommunityReport, ReportVote, 
                                  UserReputation, ShortLink, OrganizationMember,
                                  ForumPost, ForumComment, ForumVote)
            session.query(VerificationRecord).filter(VerificationRecord.user_id == user_id).delete()
            session.query(CommunityReport).filter(CommunityReport.reporter_id == user_id).delete()
            session.query(ReportVote).filter(ReportVote.user_id == user_id).delete()
            session.query(UserReputation).filter(UserReputation.user_id == user_id).delete()
            session.query(ShortLink).filter(ShortLink.user_id == user_id).delete()
            session.query(OrganizationMember).filter(OrganizationMember.user_id == user_id).delete()
            session.query(ForumVote).filter(ForumVote.user_id == user_id).delete()
            session.query(ForumComment).filter(ForumComment.author_id == user_id).delete()
            session.query(ForumPost).filter(ForumPost.author_id == user_id).delete()
            
            # Delete the user
            session.delete(user)
            session.commit()
            
            return {
                'success': True, 
                'message': f'User {username} ({email}) has been permanently deleted'
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def delete_user_by_email(self, email: str) -> Dict:
        """Delete a user by email address (admin function)"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            return self.delete_user(user.id)
        finally:
            session.close()
    
    def update_profile(self, user_id: int, updates: Dict) -> Dict:
        """Update user profile"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Allowed fields to update
            allowed_fields = [
                'full_name', 'avatar_url', 'desktop_notifications',
                'email_notifications', 'notification_email', 'weekly_reports_enabled'
            ]
            
            for field in allowed_fields:
                if field in updates:
                    setattr(user, field, updates[field])
            
            session.commit()
            return {'success': True, 'user': user.to_dict()}
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    # ============== Dark Web Monitoring Methods ==============
    
    def get_monitored_assets(self, user_id: int) -> list:
        """Get all monitored assets for a user"""
        session = self.get_session()
        try:
            assets = session.query(MonitoredAsset).filter(
                MonitoredAsset.user_id == user_id
            ).order_by(MonitoredAsset.created_at).all()
            return [a.to_dict() for a in assets]
        finally:
            session.close()
    
    def add_monitored_asset(self, user_id: int, asset_type: str, asset_value: str, 
                            label: str = None) -> Dict:
        """Add a new asset to dark web monitoring"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            limits = user.get_plan_limits()
            if not limits.get('dark_web_monitoring'):
                return {'success': False, 'error': 'Dark web monitoring requires Pro or Enterprise subscription'}
            
            max_assets = limits.get('max_monitored_assets', 0)
            current_count = session.query(MonitoredAsset).filter(
                MonitoredAsset.user_id == user_id
            ).count()
            
            if max_assets > 0 and current_count >= max_assets:
                return {
                    'success': False,
                    'error': f'Maximum monitored assets reached ({max_assets}). Upgrade for more.'
                }
            
            # Check for duplicate
            existing = session.query(MonitoredAsset).filter(
                MonitoredAsset.user_id == user_id,
                MonitoredAsset.asset_type == asset_type,
                MonitoredAsset.asset_value == asset_value
            ).first()
            if existing:
                return {'success': False, 'error': 'This asset is already being monitored'}
            
            asset = MonitoredAsset(
                user_id=user_id,
                asset_type=asset_type,
                asset_value=asset_value,
                label=label or asset_value,
                is_active=True
            )
            session.add(asset)
            session.commit()
            
            return {
                'success': True,
                'asset': asset.to_dict(),
                'message': 'Asset added for monitoring'
            }
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def delete_monitored_asset(self, user_id: int, asset_id: int) -> Dict:
        """Remove a monitored asset and its alerts"""
        session = self.get_session()
        try:
            asset = session.query(MonitoredAsset).filter(
                MonitoredAsset.id == asset_id,
                MonitoredAsset.user_id == user_id
            ).first()
            if not asset:
                return {'success': False, 'error': 'Asset not found'}
            
            session.delete(asset)
            session.commit()
            return {'success': True, 'message': 'Asset removed from monitoring'}
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def get_dark_web_alerts(self, user_id: int, unread_only: bool = False, 
                            limit: int = 50) -> list:
        """Get dark web alerts for a user"""
        session = self.get_session()
        try:
            query = session.query(DarkWebAlert).filter(
                DarkWebAlert.user_id == user_id
            )
            if unread_only:
                query = query.filter(DarkWebAlert.is_read == False)
            alerts = query.order_by(DarkWebAlert.created_at.desc()).limit(limit).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()
    
    def get_dark_web_alert_count(self, user_id: int) -> Dict:
        """Get counts of dark web alerts"""
        session = self.get_session()
        try:
            total = session.query(DarkWebAlert).filter(DarkWebAlert.user_id == user_id).count()
            unread = session.query(DarkWebAlert).filter(
                DarkWebAlert.user_id == user_id,
                DarkWebAlert.is_read == False
            ).count()
            critical = session.query(DarkWebAlert).filter(
                DarkWebAlert.user_id == user_id,
                DarkWebAlert.severity.in_(['critical', 'high']),
                DarkWebAlert.is_resolved == False
            ).count()
            return {'total': total, 'unread': unread, 'critical': critical}
        finally:
            session.close()
    
    def mark_alert_read(self, user_id: int, alert_id: int) -> Dict:
        """Mark a dark web alert as read"""
        session = self.get_session()
        try:
            alert = session.query(DarkWebAlert).filter(
                DarkWebAlert.id == alert_id,
                DarkWebAlert.user_id == user_id
            ).first()
            if not alert:
                return {'success': False, 'error': 'Alert not found'}
            alert.is_read = True
            session.commit()
            return {'success': True}
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def mark_all_alerts_read(self, user_id: int) -> Dict:
        """Mark all dark web alerts as read"""
        session = self.get_session()
        try:
            session.query(DarkWebAlert).filter(
                DarkWebAlert.user_id == user_id,
                DarkWebAlert.is_read == False
            ).update({'is_read': True})
            session.commit()
            return {'success': True}
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def resolve_alert(self, user_id: int, alert_id: int) -> Dict:
        """Mark a dark web alert as resolved"""
        session = self.get_session()
        try:
            alert = session.query(DarkWebAlert).filter(
                DarkWebAlert.id == alert_id,
                DarkWebAlert.user_id == user_id
            ).first()
            if not alert:
                return {'success': False, 'error': 'Alert not found'}
            alert.is_resolved = True
            alert.resolved_at = datetime.utcnow()
            alert.is_read = True
            session.commit()
            return {'success': True}
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def save_scan_results(self, user_id: int, asset_id: int, scan_results: Dict) -> Dict:
        """Save dark web scan results as alerts, avoiding duplicates"""
        import json
        session = self.get_session()
        try:
            asset = session.query(MonitoredAsset).filter(
                MonitoredAsset.id == asset_id,
                MonitoredAsset.user_id == user_id
            ).first()
            if not asset:
                return {'success': False, 'error': 'Asset not found'}
            
            new_alerts = 0
            
            # Process breaches
            for breach in scan_results.get('breaches', []):
                # Check for duplicate by source_ref
                existing = session.query(DarkWebAlert).filter(
                    DarkWebAlert.asset_id == asset_id,
                    DarkWebAlert.source_ref == breach.get('name', '')
                ).first()
                if existing:
                    continue
                
                # Determine severity
                data_classes = breach.get('data_classes', [])
                severity = 'medium'
                if any(d in data_classes for d in ['Passwords', 'Credit cards', 'Social security numbers']):
                    severity = 'critical'
                elif any(d in data_classes for d in ['Phone numbers', 'Physical addresses', 'Dates of birth']):
                    severity = 'high'
                elif breach.get('is_verified'):
                    severity = 'medium'
                else:
                    severity = 'low'
                
                alert = DarkWebAlert(
                    user_id=user_id,
                    asset_id=asset_id,
                    alert_type='data_breach',
                    severity=severity,
                    title=f"Data breach: {breach.get('title', breach.get('name', 'Unknown'))}",
                    description=breach.get('description', ''),
                    source='Have I Been Pwned',
                    source_ref=breach.get('name', ''),
                    breach_date=datetime.fromisoformat(breach['breach_date']) if breach.get('breach_date') else None,
                    exposed_records=breach.get('pwn_count', 0),
                    exposed_data_types=json.dumps(data_classes)
                )
                session.add(alert)
                new_alerts += 1
            
            # Process pastes
            for paste in scan_results.get('pastes', []):
                paste_ref = f"paste-{paste.get('source', '')}-{paste.get('paste_id', '')}"
                existing = session.query(DarkWebAlert).filter(
                    DarkWebAlert.asset_id == asset_id,
                    DarkWebAlert.source_ref == paste_ref
                ).first()
                if existing:
                    continue
                
                alert = DarkWebAlert(
                    user_id=user_id,
                    asset_id=asset_id,
                    alert_type='paste_exposure',
                    severity='medium',
                    title=f"Paste exposure: {paste.get('title', paste.get('source', 'Unknown'))}",
                    description=f"Email found in paste on {paste.get('source', 'Unknown')} with {paste.get('email_count', 0)} other emails",
                    source=paste.get('source', 'Unknown'),
                    source_ref=paste_ref,
                    breach_date=datetime.fromisoformat(paste['date']) if paste.get('date') else None,
                    exposed_records=paste.get('email_count', 0)
                )
                session.add(alert)
                new_alerts += 1
            
            # Update asset stats
            asset.last_scanned = datetime.utcnow()
            asset.breach_count = len(scan_results.get('breaches', []))
            asset.paste_count = len(scan_results.get('pastes', []))
            asset.risk_level = scan_results.get('risk_level', 'unknown')
            asset.last_error = None
            
            session.commit()
            return {'success': True, 'new_alerts': new_alerts}
        except Exception as e:
            session.rollback()
            logger.error(f"Error saving scan results: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def get_monitored_asset_count(self, user_id: int) -> Dict:
        """Get monitored asset count and limits"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'current': 0, 'max': 0}
            limits = user.get_plan_limits()
            max_assets = limits.get('max_monitored_assets', 0)
            current = session.query(MonitoredAsset).filter(
                MonitoredAsset.user_id == user_id
            ).count()
            return {
                'current': current,
                'max': max_assets,
                'can_add': max_assets < 0 or current < max_assets
            }
        finally:
            session.close()
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict:
        """Change user password"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Verify old password (supports both bcrypt and legacy SHA-256)
            if not self._verify_password(old_password, user.password_hash, user.salt):
                return {'success': False, 'error': 'Current password is incorrect'}
            
            # Update password with bcrypt
            new_hash = self._hash_password(new_password)
            
            user.salt = 'bcrypt'
            user.password_hash = new_hash
            
            session.commit()
            return {'success': True, 'message': 'Password changed successfully'}
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def update_subscription(self, user_id: int, tier: str, expires_at: datetime = None) -> Dict:
        """Update user subscription tier"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            user.subscription_tier = tier
            user.subscription_expires = expires_at
            
            session.commit()
            return {
                'success': True,
                'user': user.to_dict(),
                'plan_limits': user.get_plan_limits()
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def update_stripe_customer_id(self, user_id: int, customer_id: str) -> bool:
        """Update user's Stripe customer ID"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return False
            
            user.stripe_customer_id = customer_id
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update Stripe customer ID: {e}")
            return False
        finally:
            session.close()
    
    def update_stripe_subscription_id(self, user_id: int, subscription_id: str) -> bool:
        """Update user's Stripe subscription ID"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return False
            
            user.stripe_subscription_id = subscription_id
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            logger.error(f"Failed to update Stripe subscription ID: {e}")
            return False
        finally:
            session.close()
    
    def get_user_by_subscription_id(self, subscription_id: str) -> Optional[Dict]:
        """Get user by their Stripe subscription ID"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.stripe_subscription_id == subscription_id).first()
            if user:
                return user.to_dict()
            return None
        finally:
            session.close()
    
    def get_user_by_id(self, user_id: int) -> Optional[Dict]:
        """Get user by their ID"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if user:
                return user.to_dict()
            return None
        finally:
            session.close()
    
    def get_user_by_email(self, email: str) -> Optional[Dict]:
        """Get user by email address"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if user:
                return user.to_dict()
            return None
        finally:
            session.close()
    
    def get_user_by_oauth(self, provider: str, provider_id: str) -> Optional[Dict]:
        """Get user by OAuth provider and provider ID"""
        session = self.get_session()
        try:
            user = session.query(User).filter(
                User.oauth_provider == provider,
                User.oauth_provider_id == provider_id
            ).first()
            if user:
                return user.to_dict()
            return None
        finally:
            session.close()
    
    def get_user_by_email_only(self, email: str) -> Optional[Dict]:
        """Get user by email address only (for OAuth linking)"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.email == email).first()
            if user:
                return user.to_dict()
            return None
        finally:
            session.close()
    
    def create_oauth_user(self, email: str, username: str, provider: str, provider_id: str, 
                          full_name: str = None, avatar_url: str = None) -> Dict:
        """Create a new user from OAuth login"""
        session = self.get_session()
        try:
            # Check if email already exists
            existing = session.query(User).filter(User.email == email).first()
            if existing:
                return {'success': False, 'error': 'Email already registered', 'existing_user': True}
            
            # Check if username exists, generate unique one if needed
            base_username = username
            counter = 1
            while session.query(User).filter(User.username == username).first():
                username = f"{base_username}_{counter}"
                counter += 1
            
            user = User(
                email=email,
                username=username,
                password_hash=None,  # OAuth users don't have passwords
                salt=None,
                full_name=full_name,
                avatar_url=avatar_url,
                oauth_provider=provider,
                oauth_provider_id=provider_id,
                is_verified=True  # OAuth emails are pre-verified
            )
            
            session.add(user)
            session.commit()
            
            logger.info(f"Created OAuth user: {email} via {provider}")
            return {'success': True, 'user': user.to_dict()}
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating OAuth user: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def link_oauth_to_user(self, user_id: int, provider: str, provider_id: str, avatar_url: str = None) -> Dict:
        """Link OAuth provider to existing user account"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            user.oauth_provider = provider
            user.oauth_provider_id = provider_id
            if avatar_url and not user.avatar_url:
                user.avatar_url = avatar_url
            
            session.commit()
            logger.info(f"Linked {provider} OAuth to user {user_id}")
            return {'success': True, 'user': user.to_dict()}
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error linking OAuth: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def create_session_for_oauth_user(self, user_id: int, user_agent: str = None, ip_address: str = None) -> Optional[str]:
        """Create a session for an OAuth user (bypasses password check)"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return None
            
            # Update last login
            user.last_login = datetime.utcnow()
            
            # Create session token
            token = secrets.token_urlsafe(32)
            token_hash = hashlib.sha256(token.encode()).hexdigest()
            
            # Create user session (30 day expiry)
            user_session = UserSession(
                user_id=user.id,
                token_hash=token_hash,
                expires_at=datetime.utcnow() + timedelta(days=30),
                user_agent=user_agent,
                ip_address=ip_address,
                is_persistent=True
            )
            
            session.add(user_session)
            session.commit()
            
            return token
            
        except Exception as e:
            session.rollback()
            logger.error(f"Error creating OAuth session: {e}")
            return None
        finally:
            session.close()

    def check_scan_limit(self, user_id: int) -> Dict:
        """Check if user has reached their daily scan limit"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'allowed': False, 'error': 'User not found'}
            
            limits = user.get_plan_limits()
            daily_limit = limits['daily_scans']
            
            # Unlimited scans
            if daily_limit == -1:
                return {'allowed': True, 'remaining': -1, 'limit': -1}
            
            # Get today's count
            today = datetime.utcnow().date()
            count_record = session.query(DailyScanCount).filter(
                DailyScanCount.user_id == user_id,
                DailyScanCount.date >= datetime(today.year, today.month, today.day)
            ).first()
            
            current_count = count_record.count if count_record else 0
            remaining = max(0, daily_limit - current_count)
            
            return {
                'allowed': remaining > 0,
                'remaining': remaining,
                'limit': daily_limit,
                'used': current_count
            }
            
        finally:
            session.close()
    
    def increment_scan_count(self, user_id: int) -> bool:
        """Increment daily scan count for user"""
        session = self.get_session()
        try:
            today = datetime.utcnow().date()
            today_start = datetime(today.year, today.month, today.day)
            
            count_record = session.query(DailyScanCount).filter(
                DailyScanCount.user_id == user_id,
                DailyScanCount.date >= today_start
            ).first()
            
            if count_record:
                count_record.count += 1
            else:
                count_record = DailyScanCount(
                    user_id=user_id,
                    date=today_start,
                    count=1
                )
                session.add(count_record)
            
            session.commit()
            return True
            
        except Exception as e:
            session.rollback()
            return False
        finally:
            session.close()
    
    # ============== Email Account Management ==============
    
    def get_email_accounts(self, user_id: int) -> list:
        """Get all email accounts for a user"""
        session = self.get_session()
        try:
            accounts = session.query(EmailAccount).filter(
                EmailAccount.user_id == user_id
            ).order_by(EmailAccount.created_at).all()
            return [acc.to_dict() for acc in accounts]
        finally:
            session.close()
    
    def get_email_account(self, user_id: int, account_id: int) -> Optional[Dict]:
        """Get a specific email account"""
        session = self.get_session()
        try:
            account = session.query(EmailAccount).filter(
                EmailAccount.id == account_id,
                EmailAccount.user_id == user_id
            ).first()
            return account.to_dict() if account else None
        finally:
            session.close()
    
    def get_email_account_password(self, user_id: int, account_id: int) -> Optional[str]:
        """Get the decrypted password for an email account"""
        session = self.get_session()
        try:
            account = session.query(EmailAccount).filter(
                EmailAccount.id == account_id,
                EmailAccount.user_id == user_id
            ).first()
            if account and account.password_encrypted:
                # Decrypt the password using Fernet symmetric encryption
                from security import decrypt_value
                try:
                    return decrypt_value(account.password_encrypted)
                except Exception:
                    # Fallback: try legacy base64 decoding for pre-migration data
                    import base64
                    try:
                        return base64.b64decode(account.password_encrypted.encode()).decode()
                    except Exception:
                        return None
            return None
        finally:
            session.close()
    
    def add_email_account(self, user_id: int, email: str, host: str, port: int, 
                          password: str, label: str = None) -> Dict:
        """Add a new email account for monitoring"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Check subscription limits
            limits = user.get_plan_limits()
            if not limits.get('email_monitoring'):
                return {'success': False, 'error': 'Email monitoring requires Pro or Enterprise subscription'}
            
            max_accounts = limits.get('max_email_accounts', 0)
            current_count = session.query(EmailAccount).filter(
                EmailAccount.user_id == user_id
            ).count()
            
            if current_count >= max_accounts:
                return {
                    'success': False, 
                    'error': f'Maximum email accounts reached ({max_accounts}). Upgrade for more.'
                }
            
            # Check if email already exists for this user
            existing = session.query(EmailAccount).filter(
                EmailAccount.user_id == user_id,
                EmailAccount.email == email
            ).first()
            if existing:
                return {'success': False, 'error': 'This email is already being monitored'}
            
            # Encrypt password with Fernet symmetric encryption
            from security import encrypt_value
            encrypted_password = encrypt_value(password)
            
            # Create new account
            account = EmailAccount(
                user_id=user_id,
                email=email,
                host=host,
                port=port,
                password_encrypted=encrypted_password,
                label=label or email,
                is_active=True
            )
            
            session.add(account)
            session.commit()
            
            return {
                'success': True,
                'account': account.to_dict(),
                'message': 'Email account added successfully'
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def update_email_account(self, user_id: int, account_id: int, data: Dict) -> Dict:
        """Update an existing email account"""
        session = self.get_session()
        try:
            account = session.query(EmailAccount).filter(
                EmailAccount.id == account_id,
                EmailAccount.user_id == user_id
            ).first()
            
            if not account:
                return {'success': False, 'error': 'Email account not found'}
            
            # Update allowed fields
            if 'host' in data:
                account.host = data['host']
            if 'port' in data:
                account.port = data['port']
            if 'label' in data:
                account.label = data['label']
            if 'is_active' in data:
                account.is_active = data['is_active']
            if 'check_frequency' in data:
                account.check_frequency = data['check_frequency']
            if 'password' in data and data['password']:
                from security import encrypt_value
                account.password_encrypted = encrypt_value(data['password'])
            
            session.commit()
            return {
                'success': True,
                'account': account.to_dict(),
                'message': 'Email account updated'
            }
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def delete_email_account(self, user_id: int, account_id: int) -> Dict:
        """Delete an email account"""
        session = self.get_session()
        try:
            account = session.query(EmailAccount).filter(
                EmailAccount.id == account_id,
                EmailAccount.user_id == user_id
            ).first()
            
            if not account:
                return {'success': False, 'error': 'Email account not found'}
            
            session.delete(account)
            session.commit()
            
            return {'success': True, 'message': 'Email account deleted'}
            
        except Exception as e:
            session.rollback()
            logger.error(f"Operation failed: {e}", exc_info=True)
            return {'success': False, 'error': 'An internal error occurred'}
        finally:
            session.close()
    
    def get_active_email_accounts(self, user_id: int) -> list:
        """Get all active email accounts with decrypted passwords for monitoring"""
        session = self.get_session()
        try:
            accounts = session.query(EmailAccount).filter(
                EmailAccount.user_id == user_id,
                EmailAccount.is_active == True
            ).all()
            
            from security import decrypt_value
            import base64
            result = []
            for acc in accounts:
                password = None
                if acc.password_encrypted:
                    try:
                        password = decrypt_value(acc.password_encrypted)
                    except Exception:
                        # Fallback for legacy base64 data
                        try:
                            password = base64.b64decode(acc.password_encrypted.encode()).decode()
                        except Exception:
                            password = None
                result.append({
                    'id': acc.id,
                    'email': acc.email,
                    'host': acc.host,
                    'port': acc.port,
                    'password': password,
                    'label': acc.label
                })
            return result
        finally:
            session.close()
    
    def update_email_account_status(self, account_id: int, checked: bool = True, error: str = None):
        """Update the status of an email account after checking"""
        session = self.get_session()
        try:
            account = session.query(EmailAccount).filter(EmailAccount.id == account_id).first()
            if account:
                account.last_checked = datetime.utcnow()
                account.is_verified = checked and not error
                account.last_error = error
                session.commit()
        except:
            session.rollback()
        finally:
            session.close()
    
    def get_email_account_count(self, user_id: int) -> Dict:
        """Get email account count and limits for a user"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'current': 0, 'max': 0}
            
            limits = user.get_plan_limits()
            max_accounts = limits.get('max_email_accounts', 0)
            
            current_count = session.query(EmailAccount).filter(
                EmailAccount.user_id == user_id
            ).count()
            
            return {
                'current': current_count,
                'max': max_accounts,
                'can_add': current_count < max_accounts
            }
        finally:
            session.close()
    
    def cleanup_expired_sessions(self):
        """Remove expired sessions from database"""
        session = self.get_session()
        try:
            session.query(UserSession).filter(
                UserSession.expires_at < datetime.utcnow()
            ).delete()
            session.commit()
        finally:
            session.close()


# Subscription pricing info
SUBSCRIPTION_PLANS = {
    'free': {
        'name': 'Free',
        'price': 0,
        'period': 'forever',
        'max_monitored_assets': 0,
        'features': [
            '25 link scans per day',
            'Basic threat detection',
            'Security scorecard & grade',
            '7-day scan history',
            'Browser extension',
            'Desktop notifications'
        ],
        'limitations': [
            'No dark web monitoring',
            'No Compliance Center',
            'No Attack Surface Monitoring',
            'No API access'
        ]
    },
    'pro': {
        'name': 'Pro',
        'price': 14.99,
        'period': 'month',
        'max_monitored_assets': 5,
        'features': [
            'Unlimited link scans',
            'Advanced threat detection',
            'Full scan history',
            'Dark web monitoring (5 assets)',
            'Compliance Center (SOC 2, ISO 27001, GDPR)',
            'API access',
            'Whitelist/Blacklist',
            'Export reports',
            'Email support'
        ],
        'limitations': [
            'No Attack Surface Monitoring',
            'No AI remediation advice'
        ]
    },
    'enterprise': {
        'name': 'Enterprise',
        'price': 59.99,
        'period': 'month',
        'max_monitored_assets': -1,
        'features': [
            'Unlimited link scans',
            'Everything in Pro',
            'Unlimited dark web monitoring',
            'Attack Surface Monitoring (25 domains, hourly)',
            'Compliance Center with exportable reports',
            'AI-powered remediation advice',
            'Team management',
            'Scheduled reports',
            'Priority support'
        ],
        'limitations': []
    }
}


# Global auth manager instance
auth_manager = AuthManager()
