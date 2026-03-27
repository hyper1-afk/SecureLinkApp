"""
Database models for the SecureLink application.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from sqlalchemy import create_engine, Column, Integer, String, Float, Boolean, DateTime, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import secrets
import hashlib

from config import Config

Base = declarative_base()


class VerificationRecord(Base):
    """Record of a link verification"""
    __tablename__ = 'verification_records'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    url_hash = Column(String(64), nullable=False, index=True)  # SHA256 hash for quick lookup
    is_safe = Column(Boolean, nullable=False)
    risk_level = Column(String(20), nullable=False)
    risk_score = Column(Float, nullable=False)
    threats_detected = Column(JSON, default=list)
    warnings = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    ai_explanation = Column(Text, nullable=True)  # AI-generated threat explanation
    source = Column(String(50), default='manual')  # 'manual', 'email', 'api', 'extension', 'shortlink'
    email_subject = Column(String(500), nullable=True)
    email_from = Column(String(255), nullable=True)
    email_account = Column(String(255), nullable=True)  # Which monitored email account received this
    user_id = Column(Integer, nullable=True)  # User who owns this verification
    organization_id = Column(Integer, nullable=True)  # Organization for enterprise features
    verified_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'url': self.url,
            'is_safe': self.is_safe,
            'risk_level': self.risk_level,
            'risk_score': self.risk_score,
            'threats_detected': self.threats_detected,
            'warnings': self.warnings,
            'source': self.source,
            'email_subject': self.email_subject,
            'email_from': self.email_from,
            'email_account': self.email_account,
            'user_id': self.user_id,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class WhitelistedDomain(Base):
    """Domains that are always considered safe"""
    __tablename__ = 'whitelisted_domains'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, unique=True)
    added_by = Column(String(100), default='user')
    added_at = Column(DateTime, default=datetime.utcnow)
    notes = Column(Text, nullable=True)


class BlacklistedDomain(Base):
    """Domains that are always considered dangerous"""
    __tablename__ = 'blacklisted_domains'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, unique=True)
    reason = Column(String(500), nullable=True)
    added_by = Column(String(100), default='user')
    added_at = Column(DateTime, default=datetime.utcnow)


class ShortLink(Base):
    """Safe link shortener records"""
    __tablename__ = 'short_links'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    short_code = Column(String(10), nullable=False, unique=True, index=True)
    original_url = Column(String(2048), nullable=False)
    is_safe = Column(Boolean, nullable=False, default=True)
    risk_score = Column(Float, default=0)
    click_count = Column(Integer, default=0)
    user_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'short_code': self.short_code,
            'original_url': self.original_url,
            'is_safe': self.is_safe,
            'risk_score': self.risk_score,
            'click_count': self.click_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None
        }


class CommunityReport(Base):
    """Community-reported suspicious links"""
    __tablename__ = 'community_reports'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(String(2048), nullable=False, index=True)
    url_hash = Column(String(64), nullable=False, index=True)
    report_type = Column(String(50), nullable=False)  # 'phishing', 'malware', 'scam', 'spam', 'other'
    description = Column(Text, nullable=True)
    reporter_id = Column(Integer, nullable=False)
    status = Column(String(20), default='pending')  # 'pending', 'verified', 'rejected'
    votes_up = Column(Integer, default=0)
    votes_down = Column(Integer, default=0)
    verified_by_id = Column(Integer, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'url': self.url,
            'report_type': self.report_type,
            'description': self.description,
            'status': self.status,
            'votes_up': self.votes_up,
            'votes_down': self.votes_down,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ReportVote(Base):
    """Votes on community reports"""
    __tablename__ = 'report_votes'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    report_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False)
    vote = Column(Integer, nullable=False)  # 1 = upvote, -1 = downvote
    created_at = Column(DateTime, default=datetime.utcnow)


class UserReputation(Base):
    """User reputation/karma tracking"""
    __tablename__ = 'user_reputation'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, unique=True, index=True)
    karma = Column(Integer, default=0)
    reports_submitted = Column(Integer, default=0)
    reports_verified = Column(Integer, default=0)
    reports_rejected = Column(Integer, default=0)
    votes_cast = Column(Integer, default=0)
    badge_level = Column(String(20), default='newcomer')  # 'newcomer', 'contributor', 'trusted', 'expert'
    updated_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'karma': self.karma,
            'reports_submitted': self.reports_submitted,
            'reports_verified': self.reports_verified,
            'badge_level': self.badge_level
        }


class Organization(Base):
    """Organizations for enterprise features"""
    __tablename__ = 'organizations'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    domain = Column(String(255), nullable=True)  # Auto-join by email domain
    owner_id = Column(Integer, nullable=False)
    api_key = Column(String(64), nullable=True, unique=True)
    slack_webhook = Column(String(500), nullable=True)
    discord_webhook = Column(String(500), nullable=True)
    teams_webhook = Column(String(500), nullable=True)
    custom_blocked_domains = Column(JSON, default=list)
    settings = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'domain': self.domain,
            'has_slack': bool(self.slack_webhook),
            'has_discord': bool(self.discord_webhook),
            'has_teams': bool(self.teams_webhook),
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class OrganizationMember(Base):
    """Organization membership"""
    __tablename__ = 'organization_members'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    role = Column(String(20), default='member')  # 'owner', 'admin', 'member'
    joined_at = Column(DateTime, default=datetime.utcnow)


class ThreatEvent(Base):
    """Global threat events for threat map"""
    __tablename__ = 'threat_events'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    threat_type = Column(String(50), nullable=False)
    domain = Column(String(255), nullable=True)
    country_code = Column(String(2), nullable=True)
    latitude = Column(Float, nullable=True)
    longitude = Column(Float, nullable=True)
    severity = Column(String(20), default='medium')
    description = Column(String(500), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'threat_type': self.threat_type,
            'domain': self.domain,
            'country_code': self.country_code,
            'latitude': self.latitude,
            'longitude': self.longitude,
            'severity': self.severity,
            'description': self.description,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


# ==================== CORPORATE GATEWAY LOG ====================

class OrgGatewayLog(Base):
    """Audit log for all corporate gateway URL checks"""
    __tablename__ = 'org_gateway_logs'

    id = Column(Integer, primary_key=True, autoincrement=True)
    organization_id = Column(Integer, nullable=False, index=True)
    user_id = Column(Integer, nullable=True, index=True)   # NULL = anonymous API key call
    url = Column(String(2048), nullable=False)
    domain = Column(String(255), nullable=True, index=True)
    verdict = Column(String(10), nullable=False)           # 'allow' | 'block'
    block_reason = Column(String(255), nullable=True)      # why it was blocked
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(20), nullable=True)
    threats = Column(JSON, default=list)
    source_ip = Column(String(64), nullable=True)
    checked_at = Column(DateTime, default=datetime.utcnow, index=True)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'organization_id': self.organization_id,
            'user_id': self.user_id,
            'url': self.url,
            'domain': self.domain,
            'verdict': self.verdict,
            'block_reason': self.block_reason,
            'risk_score': self.risk_score,
            'risk_level': self.risk_level,
            'threats': self.threats or [],
            'source_ip': self.source_ip,
            'checked_at': self.checked_at.isoformat() if self.checked_at else None,
        }


# ==================== FORUM / COMMUNITY CHAT MODELS ====================

class ForumCategory(Base):
    """Forum categories/rooms (like subreddits)"""
    __tablename__ = 'forum_categories'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(100), nullable=False, unique=True)
    slug = Column(String(100), nullable=False, unique=True, index=True)
    description = Column(Text, nullable=True)
    icon = Column(String(50), default='fa-comments')  # FontAwesome icon
    color = Column(String(20), default='blue')  # Tailwind color
    post_count = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    sort_order = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'name': self.name,
            'slug': self.slug,
            'description': self.description,
            'icon': self.icon,
            'color': self.color,
            'post_count': self.post_count,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }


class ForumPost(Base):
    """Forum posts/threads"""
    __tablename__ = 'forum_posts'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    category_id = Column(Integer, ForeignKey('forum_categories.id'), nullable=False, index=True)
    author_id = Column(Integer, nullable=False, index=True)
    author_username = Column(String(100), nullable=False)
    title = Column(String(300), nullable=False)
    content = Column(Text, nullable=False)
    upvotes = Column(Integer, default=0)
    downvotes = Column(Integer, default=0)
    comment_count = Column(Integer, default=0)
    view_count = Column(Integer, default=0)
    is_pinned = Column(Boolean, default=False)
    is_locked = Column(Boolean, default=False)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self, include_content=True) -> Dict:
        data = {
            'id': self.id,
            'category_id': self.category_id,
            'author_id': self.author_id,
            'author_username': self.author_username,
            'title': self.title,
            'upvotes': self.upvotes,
            'downvotes': self.downvotes,
            'score': self.upvotes - self.downvotes,
            'comment_count': self.comment_count,
            'view_count': self.view_count,
            'is_pinned': self.is_pinned,
            'is_locked': self.is_locked,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
        if include_content:
            data['content'] = self.content
        return data


class ForumComment(Base):
    """Comments on forum posts"""
    __tablename__ = 'forum_comments'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    post_id = Column(Integer, ForeignKey('forum_posts.id'), nullable=False, index=True)
    parent_id = Column(Integer, ForeignKey('forum_comments.id'), nullable=True, index=True)  # For nested replies
    author_id = Column(Integer, nullable=False, index=True)
    author_username = Column(String(100), nullable=False)
    content = Column(Text, nullable=False)
    upvotes = Column(Integer, default=0)
    downvotes = Column(Integer, default=0)
    is_deleted = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'post_id': self.post_id,
            'parent_id': self.parent_id,
            'author_id': self.author_id,
            'author_username': self.author_username,
            'content': self.content,
            'upvotes': self.upvotes,
            'downvotes': self.downvotes,
            'score': self.upvotes - self.downvotes,
            'is_deleted': self.is_deleted,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }


class ForumVote(Base):
    """Votes on posts and comments"""
    __tablename__ = 'forum_votes'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    post_id = Column(Integer, nullable=True, index=True)  # Either post_id or comment_id
    comment_id = Column(Integer, nullable=True, index=True)
    vote = Column(Integer, nullable=False)  # 1 = upvote, -1 = downvote
    created_at = Column(DateTime, default=datetime.utcnow)


class AnonQuota(Base):
    """Per-browser daily quota tracking for anonymous public tools."""
    __tablename__ = 'anon_quotas'

    id        = Column(Integer, primary_key=True, autoincrement=True)
    anon_id   = Column(String(36), nullable=False, index=True)  # sl_anon_id cookie value
    action    = Column(String(8),  nullable=False)              # 'lnk', 'hc', 'bc'
    scan_date = Column(String(10), nullable=False)              # YYYY-MM-DD
    count     = Column(Integer,    nullable=False, default=0)


class HealthCheckWatch(Base):
    """Pro-tier: track domains a user wants daily score-drop alerts for."""
    __tablename__ = 'health_check_watches'

    id              = Column(Integer,  primary_key=True, autoincrement=True)
    user_id         = Column(Integer,  nullable=False, index=True)
    domain          = Column(String(253), nullable=False)
    last_score      = Column(Integer,  nullable=True)
    last_checked_at = Column(DateTime, nullable=True)
    created_at      = Column(DateTime, default=datetime.utcnow)


class Database:
    """Database manager class"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        
        # Use shared database engine
        from db_engine import get_database_engine, safe_create_tables
        self.engine = get_database_engine(self.config)
        
        # Only create tables if they don't exist (safe for production)
        safe_create_tables(Base.metadata, self.engine)
        self._migrate_database()
        self.Session = sessionmaker(bind=self.engine)
        self._cleanup_old_quotas()
    
    def _migrate_database(self):
        """Add new columns if they don't exist (simple migration)"""
        from sqlalchemy import inspect, text
        inspector = inspect(self.engine)
        
        # Check verification_records table for new columns
        if 'verification_records' in inspector.get_table_names():
            columns = [col['name'] for col in inspector.get_columns('verification_records')]
            
            with self.engine.connect() as conn:
                if 'email_account' not in columns:
                    conn.execute(text('ALTER TABLE verification_records ADD COLUMN email_account VARCHAR(255)'))
                    conn.commit()
                if 'user_id' not in columns:
                    conn.execute(text('ALTER TABLE verification_records ADD COLUMN user_id INTEGER'))
                    conn.commit()
                if 'organization_id' not in columns:
                    conn.execute(text('ALTER TABLE verification_records ADD COLUMN organization_id INTEGER'))
                    conn.commit()
                if 'ai_explanation' not in columns:
                    conn.execute(text('ALTER TABLE verification_records ADD COLUMN ai_explanation TEXT'))
                    conn.commit()
    
    def get_session(self):
        return self.Session()

    # ── Anonymous quota (DB-backed, persists across restarts) ──────────────

    def _cleanup_old_quotas(self):
        """Delete quota rows from previous days — called once at startup."""
        from datetime import date
        today = date.today().isoformat()
        session = self.Session()
        try:
            session.query(AnonQuota).filter(AnonQuota.scan_date < today).delete()
            session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    def get_anon_quota_remaining(self, anon_id: str, action: str, limit: int) -> int:
        """Return how many uses remain for this browser today."""
        from datetime import date
        today = date.today().isoformat()
        session = self.Session()
        try:
            row = session.query(AnonQuota).filter_by(
                anon_id=anon_id, action=action, scan_date=today
            ).first()
            used = row.count if row else 0
            return max(0, limit - used)
        finally:
            session.close()

    def check_and_increment_anon_quota(self, anon_id: str, action: str, limit: int) -> bool:
        """Atomically check quota and increment if under limit. Returns True if allowed."""
        from datetime import date
        today = date.today().isoformat()
        session = self.Session()
        try:
            row = session.query(AnonQuota).filter_by(
                anon_id=anon_id, action=action, scan_date=today
            ).first()
            if row:
                if row.count >= limit:
                    return False
                row.count += 1
            else:
                row = AnonQuota(anon_id=anon_id, action=action, scan_date=today, count=1)
                session.add(row)
            session.commit()
            return True
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()

    # ── Health Check Watch (Pro) ─────────────────────────────────────────

    def add_health_watch(self, user_id: int, domain: str) -> bool:
        """Add a domain to a user's watch list (idempotent)."""
        session = self.Session()
        try:
            existing = session.query(HealthCheckWatch).filter_by(
                user_id=user_id, domain=domain
            ).first()
            if not existing:
                session.add(HealthCheckWatch(user_id=user_id, domain=domain))
                session.commit()
            return True
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()

    def remove_health_watch(self, user_id: int, domain: str) -> bool:
        """Remove a domain from a user's watch list."""
        session = self.Session()
        try:
            deleted = session.query(HealthCheckWatch).filter_by(
                user_id=user_id, domain=domain
            ).delete()
            session.commit()
            return deleted > 0
        except Exception:
            session.rollback()
            return False
        finally:
            session.close()

    def get_health_watches(self, user_id: int) -> List[Dict]:
        """Return all watched domains for a user."""
        session = self.Session()
        try:
            rows = session.query(HealthCheckWatch).filter_by(user_id=user_id).all()
            return [{'domain': r.domain, 'last_score': r.last_score,
                     'last_checked_at': r.last_checked_at.isoformat() if r.last_checked_at else None}
                    for r in rows]
        finally:
            session.close()

    def get_all_active_watches(self) -> List[Dict]:
        """Return all watches (used by scheduler)."""
        session = self.Session()
        try:
            rows = session.query(HealthCheckWatch).all()
            return [{'id': r.id, 'user_id': r.user_id, 'domain': r.domain,
                     'last_score': r.last_score}
                    for r in rows]
        finally:
            session.close()

    def update_health_watch_score(self, user_id: int, domain: str, score: int) -> None:
        """Update the last known score and check timestamp for a watch."""
        session = self.Session()
        try:
            row = session.query(HealthCheckWatch).filter_by(
                user_id=user_id, domain=domain
            ).first()
            if row:
                row.last_score = score
                row.last_checked_at = datetime.utcnow()
                session.commit()
        except Exception:
            session.rollback()
        finally:
            session.close()

    # ───────────────────────────────────────────────────────────────────────

    def save_verification(self, result, source: str = 'manual', 
                         email_subject: str = None, email_from: str = None,
                         email_account: str = None, user_id: int = None):
        """Save a verification result to the database"""
        import hashlib
        
        session = self.get_session()
        try:
            record = VerificationRecord(
                url=result.url,
                url_hash=hashlib.sha256(result.url.encode()).hexdigest(),
                is_safe=result.is_safe,
                risk_level=result.risk_level.value,
                risk_score=result.risk_score,
                threats_detected=result.threats_detected,
                warnings=result.warnings,
                details=result.details,
                source=source,
                email_subject=email_subject,
                email_from=email_from,
                email_account=email_account,
                user_id=user_id,
                verified_at=result.verified_at
            )
            session.add(record)
            session.commit()
            return record.id
        finally:
            session.close()
    
    def get_recent_verifications(self, limit: int = 50) -> List[Dict]:
        """Get recent verification records (all users - for admin)"""
        session = self.get_session()
        try:
            records = session.query(VerificationRecord)\
                .order_by(VerificationRecord.created_at.desc())\
                .limit(limit)\
                .all()
            return [r.to_dict() for r in records]
        finally:
            session.close()
    
    def get_user_verifications(self, user_id: int, email_accounts: List[str] = None, limit: int = 50) -> List[Dict]:
        """Get verification records for a specific user"""
        from sqlalchemy import or_
        session = self.get_session()
        try:
            # Build filter conditions
            conditions = [VerificationRecord.user_id == user_id]
            
            # Also include verifications from user's email accounts
            if email_accounts:
                conditions.append(VerificationRecord.email_account.in_(email_accounts))
            
            records = session.query(VerificationRecord)\
                .filter(or_(*conditions))\
                .order_by(VerificationRecord.created_at.desc())\
                .limit(limit)\
                .all()
            return [r.to_dict() for r in records]
        finally:
            session.close()
    
    def get_verification_by_url(self, url: str) -> Optional[Dict]:
        """Get the most recent verification for a URL"""
        import hashlib
        url_hash = hashlib.sha256(url.encode()).hexdigest()
        
        session = self.get_session()
        try:
            record = session.query(VerificationRecord)\
                .filter(VerificationRecord.url_hash == url_hash)\
                .order_by(VerificationRecord.created_at.desc())\
                .first()
            return record.to_dict() if record else None
        finally:
            session.close()
    
    def get_statistics(self, user_id: int = None) -> Dict:
        """Get verification statistics, optionally filtered by user"""
        session = self.get_session()
        try:
            q = session.query(VerificationRecord)
            if user_id is not None:
                q = q.filter(VerificationRecord.user_id == user_id)
            total = q.count()
            safe = q.filter(VerificationRecord.is_safe == True).count()
            unsafe = total - safe

            # Risk level breakdown
            risk_levels = {}
            for level in ['safe', 'low', 'medium', 'high', 'critical']:
                rq = session.query(VerificationRecord).filter(VerificationRecord.risk_level == level)
                if user_id is not None:
                    rq = rq.filter(VerificationRecord.user_id == user_id)
                risk_levels[level] = rq.count()

            return {
                'total': total,
                'safe': safe,
                'unsafe': unsafe,
                'risk_levels': risk_levels
            }
        finally:
            session.close()
    
    def add_to_whitelist(self, domain: str, notes: str = None) -> bool:
        """Add a domain to the whitelist"""
        session = self.get_session()
        try:
            existing = session.query(WhitelistedDomain)\
                .filter(WhitelistedDomain.domain == domain)\
                .first()
            if existing:
                return False
            
            record = WhitelistedDomain(domain=domain, notes=notes)
            session.add(record)
            session.commit()
            return True
        finally:
            session.close()
    
    def add_to_blacklist(self, domain: str, reason: str = None) -> bool:
        """Add a domain to the blacklist"""
        session = self.get_session()
        try:
            existing = session.query(BlacklistedDomain)\
                .filter(BlacklistedDomain.domain == domain)\
                .first()
            if existing:
                return False
            
            record = BlacklistedDomain(domain=domain, reason=reason)
            session.add(record)
            session.commit()
            return True
        finally:
            session.close()
    
    def get_whitelist(self) -> List[str]:
        """Get all whitelisted domains"""
        session = self.get_session()
        try:
            records = session.query(WhitelistedDomain).all()
            return [r.domain for r in records]
        finally:
            session.close()
    
    def get_blacklist(self) -> List[str]:
        """Get all blacklisted domains"""
        session = self.get_session()
        try:
            records = session.query(BlacklistedDomain).all()
            return [r.domain for r in records]
        finally:
            session.close()
    
    # ============== Short Link Methods ==============
    
    def create_short_link(self, url: str, is_safe: bool, risk_score: float, user_id: int = None) -> Dict:
        """Create a shortened link"""
        session = self.get_session()
        try:
            # Generate unique short code
            while True:
                short_code = secrets.token_urlsafe(6)[:8]
                existing = session.query(ShortLink).filter(ShortLink.short_code == short_code).first()
                if not existing:
                    break
            
            record = ShortLink(
                short_code=short_code,
                original_url=url,
                is_safe=is_safe,
                risk_score=risk_score,
                user_id=user_id
            )
            session.add(record)
            session.commit()
            return record.to_dict()
        finally:
            session.close()
    
    def get_short_link(self, short_code: str) -> Optional[Dict]:
        """Get short link by code"""
        session = self.get_session()
        try:
            record = session.query(ShortLink).filter(ShortLink.short_code == short_code).first()
            if record:
                # Increment click count
                record.click_count += 1
                session.commit()
                return record.to_dict()
            return None
        finally:
            session.close()
    
    def get_user_short_links(self, user_id: int) -> List[Dict]:
        """Get all short links created by a user"""
        session = self.get_session()
        try:
            records = session.query(ShortLink).filter(ShortLink.user_id == user_id)\
                .order_by(ShortLink.created_at.desc()).limit(100).all()
            return [r.to_dict() for r in records]
        finally:
            session.close()
    
    def track_short_link_click(self, short_code: str) -> bool:
        """Track a click on a short link"""
        session = self.get_session()
        try:
            record = session.query(ShortLink).filter(ShortLink.short_code == short_code).first()
            if record:
                record.click_count += 1
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    # ============== Community Report Methods ==============
    
    def create_community_report(self, url: str, reported_by: int, report_type: str, description: str) -> Dict:
        """Create a community report"""
        session = self.get_session()
        try:
            url_hash = hashlib.sha256(url.encode()).hexdigest()
            
            record = CommunityReport(
                url=url,
                url_hash=url_hash,
                report_type=report_type,
                description=description,
                reporter_id=reported_by
            )
            session.add(record)
            
            # Update user reputation
            rep = session.query(UserReputation).filter(UserReputation.user_id == reported_by).first()
            if not rep:
                rep = UserReputation(user_id=reported_by)
                session.add(rep)
            rep.reports_submitted += 1
            rep.karma += 5  # Karma for reporting
            
            session.commit()
            return record.to_dict()
        finally:
            session.close()
    
    def get_community_reports(self, status: str = None, limit: int = 50) -> List[Dict]:
        """Get community reports"""
        session = self.get_session()
        try:
            query = session.query(CommunityReport)
            if status:
                query = query.filter(CommunityReport.status == status)
            records = query.order_by(CommunityReport.created_at.desc()).limit(limit).all()
            return [r.to_dict() for r in records]
        finally:
            session.close()
    
    def vote_on_report(self, report_id: int, user_id: int, is_upvote: bool = True) -> Dict:
        """Vote on a community report"""
        session = self.get_session()
        try:
            # Check if already voted
            existing = session.query(ReportVote).filter(
                ReportVote.report_id == report_id,
                ReportVote.user_id == user_id
            ).first()
            
            if existing:
                return {'success': False, 'error': 'Already voted'}
            
            vote = 1 if is_upvote else -1
            
            # Add vote
            record = ReportVote(report_id=report_id, user_id=user_id, vote=vote)
            session.add(record)
            
            # Update report counts
            report = session.query(CommunityReport).filter(CommunityReport.id == report_id).first()
            if report:
                if is_upvote:
                    report.votes_up += 1
                else:
                    report.votes_down += 1
                
                # Auto-verify if enough upvotes
                if report.votes_up >= 5 and report.status == 'pending':
                    report.status = 'verified'
                    # Add to blacklist
                    from urllib.parse import urlparse
                    domain = urlparse(report.url).netloc
                    if domain:
                        self.add_to_blacklist(domain, f"Community verified: {report.report_type}")
            
            # Update voter reputation
            rep = session.query(UserReputation).filter(UserReputation.user_id == user_id).first()
            if not rep:
                rep = UserReputation(user_id=user_id)
                session.add(rep)
            rep.votes_cast += 1
            rep.karma += 1
            
            session.commit()
            return {'success': True}
        finally:
            session.close()
    
    def get_user_reputation(self, user_id: int) -> Dict:
        """Get user reputation"""
        session = self.get_session()
        try:
            rep = session.query(UserReputation).filter(UserReputation.user_id == user_id).first()
            if rep:
                return rep.to_dict()
            return {'karma': 0, 'reports_submitted': 0, 'reports_verified': 0, 'badge_level': 'newcomer'}
        finally:
            session.close()
    
    def update_user_reputation(self, user_id: int, karma_change: int = 0) -> Dict:
        """Update user reputation karma"""
        session = self.get_session()
        try:
            rep = session.query(UserReputation).filter(UserReputation.user_id == user_id).first()
            if not rep:
                rep = UserReputation(user_id=user_id)
                session.add(rep)
            
            rep.karma += karma_change
            
            # Update badge level based on karma
            if rep.karma >= 1000:
                rep.badge_level = 'diamond'
            elif rep.karma >= 500:
                rep.badge_level = 'platinum'
            elif rep.karma >= 200:
                rep.badge_level = 'gold'
            elif rep.karma >= 100:
                rep.badge_level = 'silver'
            elif rep.karma >= 50:
                rep.badge_level = 'bronze'
            else:
                rep.badge_level = 'newcomer'
            
            session.commit()
            return rep.to_dict()
        finally:
            session.close()
    
    def get_reputation_leaderboard(self, limit: int = 10) -> List[Dict]:
        """Get top users by karma"""
        session = self.get_session()
        try:
            reps = session.query(UserReputation)\
                .order_by(UserReputation.karma.desc())\
                .limit(limit).all()
            
            results = []
            for rep in reps:
                data = rep.to_dict()
                # Get username
                user = session.query(User).filter(User.id == rep.user_id).first()
                if user:
                    data['username'] = user.username
                results.append(data)
            return results
        finally:
            session.close()
    
    # ============== Organization Methods ==============
    
    def create_organization(self, name: str, owner_id: int, domain: str = None) -> Dict:
        """Create an organization"""
        session = self.get_session()
        try:
            api_key = secrets.token_hex(32)
            
            org = Organization(
                name=name,
                domain=domain,
                owner_id=owner_id,
                api_key=api_key
            )
            session.add(org)
            session.flush()
            
            # Add owner as member
            member = OrganizationMember(
                organization_id=org.id,
                user_id=owner_id,
                role='owner'
            )
            session.add(member)
            session.commit()
            
            result = org.to_dict()
            result['api_key'] = api_key
            return result
        finally:
            session.close()
    
    def get_organization(self, org_id: int) -> Optional[Dict]:
        """Get organization by ID"""
        session = self.get_session()
        try:
            org = session.query(Organization).filter(Organization.id == org_id).first()
            return org.to_dict() if org else None
        finally:
            session.close()
    
    def is_organization_member(self, org_id: int, user_id: int) -> bool:
        """Check if user is a member of the organization"""
        session = self.get_session()
        try:
            member = session.query(OrganizationMember).filter(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == user_id
            ).first()
            return member is not None
        finally:
            session.close()
    
    def get_organization_member(self, org_id: int, user_id: int) -> Optional[Dict]:
        """Get organization member details"""
        session = self.get_session()
        try:
            member = session.query(OrganizationMember).filter(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == user_id
            ).first()
            return member.to_dict() if member else None
        finally:
            session.close()
    
    def get_organization_members(self, org_id: int) -> List[Dict]:
        """Get all members of an organization"""
        session = self.get_session()
        try:
            members = session.query(OrganizationMember).filter(
                OrganizationMember.organization_id == org_id
            ).all()
            results = []
            for m in members:
                data = m.to_dict()
                user = session.query(User).filter(User.id == m.user_id).first()
                if user:
                    data['username'] = user.username
                    data['email'] = user.email
                results.append(data)
            return results
        finally:
            session.close()
    
    def add_organization_member(self, org_id: int, user_id: int, role: str = 'member') -> Optional[Dict]:
        """Add a member to an organization"""
        session = self.get_session()
        try:
            # Check if already a member
            existing = session.query(OrganizationMember).filter(
                OrganizationMember.organization_id == org_id,
                OrganizationMember.user_id == user_id
            ).first()
            if existing:
                return None
            
            member = OrganizationMember(
                organization_id=org_id,
                user_id=user_id,
                role=role
            )
            session.add(member)
            session.commit()
            return member.to_dict()
        finally:
            session.close()
    
    def get_user_organization(self, user_id: int) -> Optional[Dict]:
        """Get the organization a user belongs to"""
        session = self.get_session()
        try:
            member = session.query(OrganizationMember).filter(OrganizationMember.user_id == user_id).first()
            if member:
                org = session.query(Organization).filter(Organization.id == member.organization_id).first()
                if org:
                    result = org.to_dict()
                    result['role'] = member.role
                    return result
            return None
        finally:
            session.close()
    
    def update_organization_webhooks(self, org_id: int, slack_webhook: str = None, discord_webhook: str = None, teams_webhook: str = None) -> bool:
        """Update organization webhook URLs"""
        session = self.get_session()
        try:
            org = session.query(Organization).filter(Organization.id == org_id).first()
            if org:
                if slack_webhook is not None:
                    org.slack_webhook = slack_webhook
                if discord_webhook is not None:
                    org.discord_webhook = discord_webhook
                if teams_webhook is not None:
                    org.teams_webhook = teams_webhook
                session.commit()
                return True
            return False
        finally:
            session.close()
    
    def get_organization_stats(self, org_id: int) -> Dict:
        """Get organization scan statistics"""
        session = self.get_session()
        try:
            members = session.query(OrganizationMember).filter(OrganizationMember.organization_id == org_id).all()
            user_ids = [m.user_id for m in members]
            
            total = session.query(VerificationRecord).filter(VerificationRecord.user_id.in_(user_ids)).count()
            unsafe = session.query(VerificationRecord).filter(
                VerificationRecord.user_id.in_(user_ids),
                VerificationRecord.is_safe == False
            ).count()
            
            return {
                'total_scans': total,
                'unsafe_detected': unsafe,
                'member_count': len(members)
            }
        finally:
            session.close()

    # ============== Corporate Gateway Methods ==============

    def get_org_by_api_key(self, api_key: str) -> Optional[Dict]:
        """Look up an organization by its API key"""
        session = self.get_session()
        try:
            org = session.query(Organization).filter(Organization.api_key == api_key).first()
            if not org:
                return None
            result = org.to_dict()
            result['id'] = org.id
            result['owner_id'] = org.owner_id
            result['settings'] = org.settings or {}
            result['custom_blocked_domains'] = org.custom_blocked_domains or []
            return result
        finally:
            session.close()

    def get_org_policy(self, org_id: int) -> Dict:
        """Return the policy config stored in org.settings"""
        session = self.get_session()
        try:
            org = session.query(Organization).filter(Organization.id == org_id).first()
            if not org:
                return {}
            settings = org.settings or {}
            return settings.get('policy', {})
        finally:
            session.close()

    def set_org_policy(self, org_id: int, policy: Dict) -> bool:
        """Persist policy config into org.settings['policy']"""
        session = self.get_session()
        try:
            org = session.query(Organization).filter(Organization.id == org_id).first()
            if not org:
                return False
            settings = dict(org.settings or {})
            settings['policy'] = policy
            org.settings = settings
            session.commit()
            return True
        finally:
            session.close()

    def log_gateway_check(self, org_id: int, url: str, verdict: str,
                          block_reason: str = None, risk_score: float = None,
                          risk_level: str = None, threats: list = None,
                          user_id: int = None, source_ip: str = None) -> int:
        """Write one row to org_gateway_logs; returns the new row id"""
        from urllib.parse import urlparse
        session = self.get_session()
        try:
            parsed = urlparse(url)
            domain = parsed.netloc or url
            entry = OrgGatewayLog(
                organization_id=org_id,
                user_id=user_id,
                url=url,
                domain=domain,
                verdict=verdict,
                block_reason=block_reason,
                risk_score=risk_score,
                risk_level=risk_level,
                threats=threats or [],
                source_ip=source_ip,
            )
            session.add(entry)
            session.commit()
            return entry.id
        finally:
            session.close()

    def get_gateway_logs(self, org_id: int, limit: int = 100, offset: int = 0,
                         verdict_filter: str = None) -> List[Dict]:
        """Paginated gateway audit log for an org"""
        session = self.get_session()
        try:
            q = session.query(OrgGatewayLog).filter(OrgGatewayLog.organization_id == org_id)
            if verdict_filter in ('allow', 'block'):
                q = q.filter(OrgGatewayLog.verdict == verdict_filter)
            logs = q.order_by(OrgGatewayLog.checked_at.desc()).offset(offset).limit(limit).all()
            return [l.to_dict() for l in logs]
        finally:
            session.close()

    def get_gateway_stats(self, org_id: int) -> Dict:
        """Summary stats for the gateway dashboard widget"""
        session = self.get_session()
        try:
            total   = session.query(OrgGatewayLog).filter(OrgGatewayLog.organization_id == org_id).count()
            blocked = session.query(OrgGatewayLog).filter(
                OrgGatewayLog.organization_id == org_id,
                OrgGatewayLog.verdict == 'block'
            ).count()
            from datetime import timedelta
            since = datetime.utcnow() - timedelta(hours=24)
            today = session.query(OrgGatewayLog).filter(
                OrgGatewayLog.organization_id == org_id,
                OrgGatewayLog.checked_at >= since
            ).count()
            return {'total': total, 'blocked': blocked, 'allowed': total - blocked, 'last_24h': today}
        finally:
            session.close()

    # ============== Threat Map Methods ==============
    
    def record_threat_event(self, threat_type: str, url: str = None, country_code: str = None,
                           latitude: float = None, longitude: float = None, severity: str = 'medium') -> int:
        """Record a threat event for the map"""
        session = self.get_session()
        try:
            # Extract domain from URL if provided
            domain = None
            if url:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                domain = parsed.netloc
            
            event = ThreatEvent(
                threat_type=threat_type,
                domain=domain,
                country_code=country_code,
                latitude=latitude,
                longitude=longitude,
                severity=severity
            )
            session.add(event)
            session.commit()
            return event.id
        finally:
            session.close()
    
    def add_threat_event(self, threat_type: str, domain: str = None, country_code: str = None,
                        lat: float = None, lng: float = None, severity: str = 'medium', 
                        description: str = None) -> int:
        """Add a threat event for the map"""
        session = self.get_session()
        try:
            event = ThreatEvent(
                threat_type=threat_type,
                domain=domain,
                country_code=country_code,
                latitude=lat,
                longitude=lng,
                severity=severity,
                description=description
            )
            session.add(event)
            session.commit()
            return event.id
        finally:
            session.close()
    
    def get_recent_threat_events(self, hours: int = 24, limit: int = 100) -> List[Dict]:
        """Get recent threat events"""
        session = self.get_session()
        try:
            cutoff = datetime.utcnow() - timedelta(hours=hours)
            events = session.query(ThreatEvent).filter(ThreatEvent.created_at >= cutoff)\
                .order_by(ThreatEvent.created_at.desc()).limit(limit).all()
            return [e.to_dict() for e in events]
        finally:
            session.close()
    
    def get_threat_stats(self) -> Dict:
        """Get threat statistics"""
        session = self.get_session()
        try:
            from sqlalchemy import func
            
            today = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            
            today_count = session.query(ThreatEvent).filter(ThreatEvent.created_at >= today).count()
            total_count = session.query(ThreatEvent).count()
            
            # Threats by type
            by_type = session.query(
                ThreatEvent.threat_type,
                func.count(ThreatEvent.id)
            ).group_by(ThreatEvent.threat_type).all()
            
            return {
                'threats_today': today_count,
                'threats_total': total_count,
                'by_type': {t: c for t, c in by_type}
            }
        finally:
            session.close()
    
    def get_threat_stats_by_country(self) -> List[Dict]:
        """Get threat statistics grouped by country"""
        session = self.get_session()
        try:
            from sqlalchemy import func
            
            stats = session.query(
                ThreatEvent.country_code,
                func.count(ThreatEvent.id).label('count')
            ).group_by(ThreatEvent.country_code)\
             .order_by(func.count(ThreatEvent.id).desc())\
             .limit(20).all()
            
            return [{'country_code': cc, 'count': c} for cc, c in stats if cc]
        finally:
            session.close()


# Global database instance
db = Database()
