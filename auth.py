"""
User Authentication and Session Management
Handles user registration, login, persistent sessions, and subscriptions.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
"""
import os
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional, Dict
from dataclasses import dataclass
from enum import Enum

from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship

from config import Config

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
    
    # Email monitoring settings (encrypted)
    monitored_email = Column(String(255), nullable=True)
    monitored_email_host = Column(String(255), nullable=True)
    monitored_email_port = Column(Integer, default=993)
    monitored_email_password_encrypted = Column(Text, nullable=True)
    email_monitoring_enabled = Column(Boolean, default=False)
    
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
            'monitored_email': self.monitored_email,
            'email_monitoring_enabled': self.email_monitoring_enabled,
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
                'daily_scans': 10,
                'email_monitoring': False,
                'max_email_accounts': 0,
                'api_access': False,
                'priority_support': False,
                'advanced_analysis': False,
                'whitelist_blacklist': False,
                'export_reports': False
            },
            SubscriptionTier.PRO.value: {
                'daily_scans': 500,
                'email_monitoring': True,
                'max_email_accounts': 5,
                'api_access': True,
                'priority_support': False,
                'advanced_analysis': True,
                'whitelist_blacklist': True,
                'export_reports': True
            },
            SubscriptionTier.ENTERPRISE.value: {
                'daily_scans': -1,  # Unlimited
                'email_monitoring': True,
                'max_email_accounts': 25,
                'api_access': True,
                'priority_support': True,
                'advanced_analysis': True,
                'whitelist_blacklist': True,
                'export_reports': True
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


class AuthManager:
    """Handles user authentication and session management"""
    
    # Session duration for "remember me" - 30 days
    REMEMBER_ME_DURATION = timedelta(days=30)
    # Regular session duration - 24 hours
    SESSION_DURATION = timedelta(hours=24)
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        self.engine = create_engine(f'sqlite:///{self.config.DATABASE_PATH}')
        Base.metadata.create_all(self.engine)
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
                    conn.execute(text('ALTER TABLE users ADD COLUMN weekly_reports_enabled BOOLEAN DEFAULT 1'))
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
                    conn.execute(text('ALTER TABLE users ADD COLUMN tutorial_seen BOOLEAN DEFAULT 0'))
                    conn.commit()
    
    def get_session(self):
        return self.Session()
    
    def _hash_password(self, password: str, salt: str) -> str:
        """Hash password with salt using SHA-256"""
        return hashlib.sha256((password + salt).encode()).hexdigest()
    
    def _generate_salt(self) -> str:
        """Generate a random salt"""
        return secrets.token_hex(32)
    
    def _generate_token(self) -> str:
        """Generate a secure session token"""
        return secrets.token_urlsafe(64)
    
    def _hash_token(self, token: str) -> str:
        """Hash a session token"""
        return hashlib.sha256(token.encode()).hexdigest()
    
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
            
            # Create user
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)
            
            user = User(
                email=email,
                username=username,
                password_hash=password_hash,
                salt=salt,
                full_name=full_name,
                verification_token=secrets.token_urlsafe(32)
            )
            
            session.add(user)
            session.commit()
            
            return {
                'success': True,
                'user': user.to_dict(),
                'message': 'Account created successfully'
            }
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def login(self, email_or_username: str, password: str, remember_me: bool = False,
              device_info: str = None, ip_address: str = None) -> Dict:
        """Authenticate user and create session"""
        session = self.get_session()
        try:
            # Find user
            user = session.query(User).filter(
                (User.email == email_or_username) | (User.username == email_or_username)
            ).first()
            
            if not user:
                return {'success': False, 'error': 'Invalid credentials'}
            
            # Verify password
            password_hash = self._hash_password(password, user.salt)
            if password_hash != user.password_hash:
                return {'success': False, 'error': 'Invalid credentials'}
            
            if not user.is_active:
                return {'success': False, 'error': 'Account is deactivated'}
            
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
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def validate_token(self, token: str) -> Optional[Dict]:
        """Validate a session token and return user info"""
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
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def update_email_settings(self, user_id: int, email_settings: Dict) -> Dict:
        """Update email monitoring settings"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Check if user has Pro subscription for email monitoring
            if user.subscription_tier == SubscriptionTier.FREE.value:
                return {'success': False, 'error': 'Email monitoring requires Pro subscription'}
            
            user.monitored_email = email_settings.get('email')
            user.monitored_email_host = email_settings.get('host', 'imap.gmail.com')
            user.monitored_email_port = email_settings.get('port', 993)
            user.email_monitoring_enabled = email_settings.get('enabled', False)
            
            # In production, encrypt the password before storing
            if 'password' in email_settings:
                # Simple encoding for demo - use proper encryption in production!
                import base64
                encoded = base64.b64encode(email_settings['password'].encode()).decode()
                user.monitored_email_password_encrypted = encoded
            
            session.commit()
            return {'success': True, 'message': 'Email settings updated'}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            session.close()
    
    def get_email_settings(self, user_id: int) -> Dict:
        """Get email monitoring settings (without password)"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {}
            
            return {
                'email': user.monitored_email,
                'host': user.monitored_email_host,
                'port': user.monitored_email_port,
                'enabled': user.email_monitoring_enabled,
                'has_password': bool(user.monitored_email_password_encrypted)
            }
        finally:
            session.close()
    
    def get_decrypted_email_password(self, user_id: int) -> Optional[str]:
        """Get decrypted email password for monitoring"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user or not user.monitored_email_password_encrypted:
                return None
            
            import base64
            return base64.b64decode(user.monitored_email_password_encrypted.encode()).decode()
        finally:
            session.close()
    
    def change_password(self, user_id: int, old_password: str, new_password: str) -> Dict:
        """Change user password"""
        session = self.get_session()
        try:
            user = session.query(User).filter(User.id == user_id).first()
            if not user:
                return {'success': False, 'error': 'User not found'}
            
            # Verify old password
            old_hash = self._hash_password(old_password, user.salt)
            if old_hash != user.password_hash:
                return {'success': False, 'error': 'Current password is incorrect'}
            
            # Update password
            new_salt = self._generate_salt()
            new_hash = self._hash_password(new_password, new_salt)
            
            user.salt = new_salt
            user.password_hash = new_hash
            
            session.commit()
            return {'success': True, 'message': 'Password changed successfully'}
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
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
            return {'success': False, 'error': str(e)}
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
            logger.error(f"Error creating OAuth user: {e}")
            return {'success': False, 'error': str(e)}
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
            logger.error(f"Error linking OAuth: {e}")
            return {'success': False, 'error': str(e)}
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
                # Decrypt the password (base64 encoded)
                return base64.b64decode(account.password_encrypted.encode()).decode()
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
            
            # Encrypt password
            import base64
            encrypted_password = base64.b64encode(password.encode()).decode()
            
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
            return {'success': False, 'error': str(e)}
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
                import base64
                account.password_encrypted = base64.b64encode(data['password'].encode()).decode()
            
            session.commit()
            return {
                'success': True,
                'account': account.to_dict(),
                'message': 'Email account updated'
            }
            
        except Exception as e:
            session.rollback()
            return {'success': False, 'error': str(e)}
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
            return {'success': False, 'error': str(e)}
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
            
            import base64
            result = []
            for acc in accounts:
                result.append({
                    'id': acc.id,
                    'email': acc.email,
                    'host': acc.host,
                    'port': acc.port,
                    'password': base64.b64decode(acc.password_encrypted.encode()).decode() if acc.password_encrypted else None,
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
        'period': None,
        'max_scans_per_day': 10,
        'max_email_accounts': 0,
        'max_file_size_mb': 0,
        'hourly_alerts': False,
        'weekly_reports': False,
        'api_access': False,
        'features': [
            '10 link scans per day',
            'Basic threat detection',
            'Scan history (7 days)',
            'Password breach checker',
            'Security news feed',
            'Browser extension',
            'Community threat reports'
        ],
        'limitations': [
            'No file scanning',
            'No email monitoring',
            'No email alerts or reports',
            'No API access'
        ]
    },
    'pro': {
        'name': 'Pro',
        'price': 9.99,
        'period': 'month',
        'max_scans_per_day': 500,
        'max_email_accounts': 5,
        'max_file_size_mb': 50,
        'hourly_alerts': False,
        'weekly_reports': True,
        'api_access': True,
        'features': [
            '500 link scans per day',
            'Advanced AI threat detection',
            'File scanning up to 50MB',
            'Monitor up to 5 email accounts',
            'Weekly security email reports',
            'Full scan history',
            'API access',
            'Whitelist/Blacklist management',
            'Export reports',
            'Priority email support'
        ],
        'limitations': [
            'No hourly threat alerts (Enterprise only)'
        ]
    },
    'enterprise': {
        'name': 'Enterprise',
        'price': 49.99,
        'period': 'month',
        'max_scans_per_day': -1,  # Unlimited
        'max_email_accounts': 25,
        'max_file_size_mb': 200,
        'hourly_alerts': True,
        'weekly_reports': True,
        'api_access': True,
        'features': [
            'Unlimited link scans',
            'Advanced AI threat detection',
            'File scanning up to 200MB',
            'Monitor up to 25 email accounts',
            'Hourly threat alerts',
            'Weekly security email reports',
            'Full scan history',
            'Full API access',
            'Custom integrations',
            'Priority phone support',
            'Team management',
            'SSO integration',
            'Dedicated account manager'
        ],
        'limitations': []
    }
}


# Global auth manager instance
auth_manager = AuthManager()
