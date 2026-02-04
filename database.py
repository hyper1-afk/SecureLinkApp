"""
Database models for the SecureLink application.

Copyright (c) 2026 Ryan Haley. All Rights Reserved.
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


class Database:
    """Database manager class"""
    
    def __init__(self, config: Config = None):
        self.config = config or Config()
        
        # Use PostgreSQL if DATABASE_URL is set, otherwise fall back to SQLite
        if self.config.DATABASE_URL:
            # Handle DigitalOcean's postgres:// vs postgresql:// URL format
            db_url = self.config.DATABASE_URL
            if db_url.startswith('postgres://'):
                db_url = db_url.replace('postgres://', 'postgresql://', 1)
            self.engine = create_engine(db_url)
        else:
            self.engine = create_engine(f'sqlite:///{self.config.DATABASE_PATH}')
        
        # Create tables only if they don't exist
        Base.metadata.create_all(self.engine, checkfirst=True)
        self._migrate_database()
        self.Session = sessionmaker(bind=self.engine)
    
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
        """Get recent verification records"""
        session = self.get_session()
        try:
            records = session.query(VerificationRecord)\
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
    
    def get_statistics(self) -> Dict:
        """Get verification statistics"""
        session = self.get_session()
        try:
            total = session.query(VerificationRecord).count()
            safe = session.query(VerificationRecord).filter(VerificationRecord.is_safe == True).count()
            unsafe = total - safe
            
            # Risk level breakdown
            risk_levels = {}
            for level in ['safe', 'low', 'medium', 'high', 'critical']:
                count = session.query(VerificationRecord)\
                    .filter(VerificationRecord.risk_level == level)\
                    .count()
                risk_levels[level] = count
            
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
