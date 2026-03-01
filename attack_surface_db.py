"""
Attack Surface Monitoring - Database Models
Models for monitored domains, scan results, findings, and alert rules.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
from datetime import datetime, timedelta
from typing import Optional, List, Dict
from sqlalchemy import (
    create_engine, Column, Integer, String, Float, Boolean, 
    DateTime, Text, JSON, ForeignKey, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
import secrets

from config import Config

Base = declarative_base()


# ============== Monitored Domains ==============

class MonitoredDomain(Base):
    """A domain being actively monitored"""
    __tablename__ = 'monitored_domains'

    id = Column(Integer, primary_key=True, autoincrement=True)
    domain = Column(String(255), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)
    organization_id = Column(Integer, nullable=True, index=True)

    # Verification: user must prove domain ownership
    is_verified = Column(Boolean, default=False)
    verification_method = Column(String(50), nullable=True)  # 'dns_txt', 'meta_tag', 'file'
    verification_token = Column(String(128), nullable=True)
    verified_at = Column(DateTime, nullable=True)

    # Scan settings
    scan_frequency = Column(String(20), default='daily')  # 'hourly', 'daily', 'weekly'
    is_active = Column(Boolean, default=True)
    notify_on_change = Column(Boolean, default=True)
    notify_on_critical = Column(Boolean, default=True)

    # Latest scan snapshot
    latest_score = Column(Integer, nullable=True)
    latest_grade = Column(String(5), nullable=True)
    latest_scan_at = Column(DateTime, nullable=True)
    previous_score = Column(Integer, nullable=True)  # For change detection

    # Metadata
    label = Column(String(100), nullable=True)  # User-friendly name
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # IDS Baseline (auto-set on first scan, user-resettable)
    baseline_ports           = Column(JSON,        nullable=True)
    baseline_ssl_fingerprint = Column(String(128), nullable=True)
    baseline_ssl_issuer      = Column(String(255), nullable=True)
    baseline_dns             = Column(JSON,        nullable=True)
    baseline_content_hash    = Column(String(64),  nullable=True)
    baseline_set_at          = Column(DateTime,    nullable=True)

    # Relationships
    scan_results = relationship("DomainScanRecord", back_populates="monitored_domain",
                                cascade="all, delete-orphan", order_by="desc(DomainScanRecord.created_at)")

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'domain': self.domain,
            'user_id': self.user_id,
            'organization_id': self.organization_id,
            'is_verified': self.is_verified,
            'verification_method': self.verification_method,
            'verified_at': self.verified_at.isoformat() if self.verified_at else None,
            'scan_frequency': self.scan_frequency,
            'is_active': self.is_active,
            'notify_on_change': self.notify_on_change,
            'notify_on_critical': self.notify_on_critical,
            'latest_score': self.latest_score,
            'latest_grade': self.latest_grade,
            'latest_scan_at': self.latest_scan_at.isoformat() if self.latest_scan_at else None,
            'previous_score': self.previous_score,
            'score_change': (self.latest_score - self.previous_score) if self.latest_score is not None and self.previous_score is not None else None,
            'label': self.label,
            'notes': self.notes,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'baseline_ports': self.baseline_ports,
            'baseline_ssl_fingerprint': self.baseline_ssl_fingerprint,
            'baseline_ssl_issuer': self.baseline_ssl_issuer,
            'baseline_dns': self.baseline_dns,
            'baseline_content_hash': self.baseline_content_hash,
            'baseline_set_at': self.baseline_set_at.isoformat() if self.baseline_set_at else None,
        }

    def generate_verification_token(self) -> str:
        """Generate a unique token for domain verification"""
        self.verification_token = f"securelink-verify-{secrets.token_hex(16)}"
        return self.verification_token


# ============== Scan Results ==============

class DomainScanRecord(Base):
    """A single scan result for a monitored domain"""
    __tablename__ = 'domain_scan_records'

    id = Column(Integer, primary_key=True, autoincrement=True)
    monitored_domain_id = Column(Integer, ForeignKey('monitored_domains.id'), nullable=False, index=True)
    domain = Column(String(255), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)

    # Score
    score = Column(Integer, nullable=False)  # 0-100
    grade = Column(String(5), nullable=False)

    # Findings summary
    findings_critical = Column(Integer, default=0)
    findings_high = Column(Integer, default=0)
    findings_medium = Column(Integer, default=0)
    findings_low = Column(Integer, default=0)
    findings_info = Column(Integer, default=0)
    findings_total = Column(Integer, default=0)

    # Detailed results (JSON)
    findings = Column(JSON, default=list)
    ssl_info = Column(JSON, default=dict)
    headers_info = Column(JSON, default=dict)
    dns_info = Column(JSON, default=dict)
    whois_info = Column(JSON, default=dict)
    technology_info = Column(JSON, default=dict)
    breach_info = Column(JSON, default=dict)
    port_info = Column(JSON, default=dict)

    # Performance
    scan_duration_ms = Column(Integer, default=0)
    scan_source = Column(String(20), default='scheduled')  # 'manual', 'scheduled', 'api'

    # AI analysis
    ai_summary = Column(Text, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)

    # Relationships
    monitored_domain = relationship("MonitoredDomain", back_populates="scan_results")

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'monitored_domain_id': self.monitored_domain_id,
            'domain': self.domain,
            'score': self.score,
            'grade': self.grade,
            'findings_summary': {
                'critical': self.findings_critical,
                'high': self.findings_high,
                'medium': self.findings_medium,
                'low': self.findings_low,
                'info': self.findings_info,
                'total': self.findings_total,
            },
            'findings': self.findings,
            'ssl_info': self.ssl_info,
            'headers_info': self.headers_info,
            'dns_info': self.dns_info,
            'whois_info': self.whois_info,
            'technology_info': self.technology_info,
            'breach_info': self.breach_info,
            'port_info': self.port_info,
            'ai_summary': self.ai_summary,
            'scan_duration_ms': self.scan_duration_ms,
            'scan_source': self.scan_source,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ============== Alert Rules ==============

class DomainAlertRule(Base):
    """Custom alert rules for domain monitoring"""
    __tablename__ = 'domain_alert_rules'

    id = Column(Integer, primary_key=True, autoincrement=True)
    monitored_domain_id = Column(Integer, ForeignKey('monitored_domains.id'), nullable=False, index=True)
    user_id = Column(Integer, nullable=False, index=True)

    # Rule definition
    rule_type = Column(String(50), nullable=False)
    # Rule types: 'score_drop', 'ssl_expiry', 'new_critical', 'score_below', 'grade_below'
    threshold = Column(String(50), nullable=True)  # e.g., '10' for 10-point drop, '30' for 30 days
    is_active = Column(Boolean, default=True)

    # Notification channels
    notify_email = Column(Boolean, default=True)
    notify_slack = Column(Boolean, default=False)
    notify_discord = Column(Boolean, default=False)
    notify_teams = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'monitored_domain_id': self.monitored_domain_id,
            'rule_type': self.rule_type,
            'threshold': self.threshold,
            'is_active': self.is_active,
            'notify_email': self.notify_email,
            'notify_slack': self.notify_slack,
            'notify_discord': self.notify_discord,
            'notify_teams': self.notify_teams,
            'created_at': self.created_at.isoformat() if self.created_at else None,
        }


# ============== Alert History ==============

class DomainAlert(Base):
    """Record of triggered alerts"""
    __tablename__ = 'domain_alerts'

    id = Column(Integer, primary_key=True, autoincrement=True)
    monitored_domain_id = Column(Integer, ForeignKey('monitored_domains.id'), nullable=False, index=True)
    alert_rule_id = Column(Integer, ForeignKey('domain_alert_rules.id'), nullable=True)
    user_id = Column(Integer, nullable=False, index=True)

    alert_type = Column(String(50), nullable=False)
    title = Column(String(255), nullable=False)
    message = Column(Text, nullable=False)
    severity = Column(String(20), default='medium')

    is_read = Column(Boolean, default=False)
    is_resolved = Column(Boolean, default=False)

    created_at = Column(DateTime, default=datetime.utcnow)
    read_at = Column(DateTime, nullable=True)
    resolved_at = Column(DateTime, nullable=True)

    def to_dict(self) -> Dict:
        return {
            'id': self.id,
            'monitored_domain_id': self.monitored_domain_id,
            'alert_type': self.alert_type,
            'title': self.title,
            'message': self.message,
            'severity': self.severity,
            'is_read': self.is_read,
            'is_resolved': self.is_resolved,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'read_at': self.read_at.isoformat() if self.read_at else None,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
        }


def _set_baseline(domain_obj: MonitoredDomain, scan_result) -> None:
    """Populate IDS baseline fields from a live DomainScanResult."""
    port_info = getattr(scan_result, 'port_info', {}) or {}
    domain_obj.baseline_ports = port_info.get('open_ports', [])

    ssl_info = scan_result.ssl_info or {}
    domain_obj.baseline_ssl_fingerprint = ssl_info.get('fingerprint')
    domain_obj.baseline_ssl_issuer = ssl_info.get('issuer')

    dns_info = scan_result.dns_info or {}
    def _extract(records, key='host'):
        out = []
        for r in (records or []):
            out.append(r[key] if isinstance(r, dict) else str(r))
        return out

    domain_obj.baseline_dns = {
        'A':   [r if isinstance(r, str) else r.get('address', str(r))
                for r in dns_info.get('a_records', [])],
        'MX':  _extract(dns_info.get('mx_records', []), 'host'),
        'NS':  _extract(dns_info.get('ns_records', []), 'host'),
        'TXT': [r if isinstance(r, str) else r.get('text', str(r))
                for r in dns_info.get('txt_records', [])],
    }

    domain_obj.baseline_content_hash = getattr(scan_result, 'content_hash', None)
    domain_obj.baseline_set_at = datetime.utcnow()


# ============== Database Manager ==============

class AttackSurfaceDB:
    """Database manager for attack surface monitoring models"""

    def __init__(self, config: Config = None):
        self.config = config or Config()

        from db_engine import get_database_engine, safe_create_tables
        self.engine = get_database_engine(self.config)
        safe_create_tables(Base.metadata, self.engine)
        self.Session = sessionmaker(bind=self.engine)
        self._run_ids_migration()

    def _run_ids_migration(self):
        """Idempotent ALTER TABLE migration for IDS columns."""
        import sqlalchemy
        insp = sqlalchemy.inspect(self.engine)

        md_cols = {c['name'] for c in insp.get_columns('monitored_domains')}
        new_md_cols = {
            'baseline_ports':           'TEXT',
            'baseline_ssl_fingerprint': 'VARCHAR(128)',
            'baseline_ssl_issuer':      'VARCHAR(255)',
            'baseline_dns':             'TEXT',
            'baseline_content_hash':    'VARCHAR(64)',
            'baseline_set_at':          'DATETIME',
        }
        with self.engine.connect() as conn:
            for col, col_type in new_md_cols.items():
                if col not in md_cols:
                    try:
                        conn.execute(sqlalchemy.text(
                            f'ALTER TABLE monitored_domains ADD COLUMN {col} {col_type}'
                        ))
                    except Exception:
                        pass

            sr_cols = {c['name'] for c in insp.get_columns('domain_scan_records')}
            if 'port_info' not in sr_cols:
                try:
                    conn.execute(sqlalchemy.text(
                        'ALTER TABLE domain_scan_records ADD COLUMN port_info TEXT'
                    ))
                except Exception:
                    pass
            try:
                conn.commit()
            except Exception:
                pass

    def get_session(self):
        return self.Session()

    # ---------- Monitored Domains ----------

    def add_domain(self, domain: str, user_id: int, organization_id: int = None,
                   label: str = None, scan_frequency: str = 'daily') -> Dict:
        """Add a domain to monitor"""
        session = self.get_session()
        try:
            # Check if already monitoring
            existing = session.query(MonitoredDomain).filter(
                MonitoredDomain.domain == domain,
                MonitoredDomain.user_id == user_id
            ).first()
            if existing:
                return {'error': 'Domain is already being monitored', 'domain': existing.to_dict()}

            md = MonitoredDomain(
                domain=domain,
                user_id=user_id,
                organization_id=organization_id,
                label=label or domain,
                scan_frequency=scan_frequency,
            )
            md.generate_verification_token()
            session.add(md)
            session.commit()
            return md.to_dict()
        finally:
            session.close()

    def get_user_domains(self, user_id: int) -> List[Dict]:
        """Get all domains monitored by a user"""
        session = self.get_session()
        try:
            domains = session.query(MonitoredDomain).filter(
                MonitoredDomain.user_id == user_id,
                MonitoredDomain.is_active == True
            ).order_by(MonitoredDomain.created_at.desc()).all()
            return [d.to_dict() for d in domains]
        finally:
            session.close()

    def get_domain(self, domain_id: int, user_id: int = None) -> Optional[Dict]:
        """Get a specific monitored domain"""
        session = self.get_session()
        try:
            query = session.query(MonitoredDomain).filter(MonitoredDomain.id == domain_id)
            if user_id:
                query = query.filter(MonitoredDomain.user_id == user_id)
            domain = query.first()
            return domain.to_dict() if domain else None
        finally:
            session.close()

    def remove_domain(self, domain_id: int, user_id: int) -> bool:
        """Remove a domain from monitoring (soft delete)"""
        session = self.get_session()
        try:
            domain = session.query(MonitoredDomain).filter(
                MonitoredDomain.id == domain_id,
                MonitoredDomain.user_id == user_id
            ).first()
            if domain:
                domain.is_active = False
                session.commit()
                return True
            return False
        finally:
            session.close()

    def verify_domain(self, domain_id: int, user_id: int, method: str = 'dns_txt') -> bool:
        """Mark a domain as verified"""
        session = self.get_session()
        try:
            domain = session.query(MonitoredDomain).filter(
                MonitoredDomain.id == domain_id,
                MonitoredDomain.user_id == user_id
            ).first()
            if domain:
                domain.is_verified = True
                domain.verification_method = method
                domain.verified_at = datetime.utcnow()
                session.commit()
                return True
            return False
        finally:
            session.close()

    def update_domain_score(self, domain_id: int, score: int, grade: str):
        """Update the latest score for a monitored domain"""
        session = self.get_session()
        try:
            domain = session.query(MonitoredDomain).filter(MonitoredDomain.id == domain_id).first()
            if domain:
                domain.previous_score = domain.latest_score
                domain.latest_score = score
                domain.latest_grade = grade
                domain.latest_scan_at = datetime.utcnow()
                session.commit()
        finally:
            session.close()

    def get_domains_due_for_scan(self) -> List[Dict]:
        """Get all domains that are due for their next scheduled scan"""
        session = self.get_session()
        try:
            now = datetime.utcnow()
            domains = session.query(MonitoredDomain).filter(
                MonitoredDomain.is_active == True,
            ).all()

            due = []
            for d in domains:
                if d.latest_scan_at is None:
                    due.append(d.to_dict())
                    continue

                if d.scan_frequency == 'hourly' and d.latest_scan_at < now - timedelta(hours=1):
                    due.append(d.to_dict())
                elif d.scan_frequency == 'daily' and d.latest_scan_at < now - timedelta(days=1):
                    due.append(d.to_dict())
                elif d.scan_frequency == 'weekly' and d.latest_scan_at < now - timedelta(weeks=1):
                    due.append(d.to_dict())

            return due
        finally:
            session.close()

    # ---------- Scan Records ----------

    def save_scan(self, monitored_domain_id: int, user_id: int, scan_result,
                  scan_source: str = 'manual') -> int:
        """Save a scan result. Accepts a DomainScanResult dataclass."""
        session = self.get_session()
        try:
            # Count findings by severity
            summary = scan_result._findings_summary() if hasattr(scan_result, '_findings_summary') else {}

            record = DomainScanRecord(
                monitored_domain_id=monitored_domain_id,
                domain=scan_result.domain,
                user_id=user_id,
                score=scan_result.score,
                grade=scan_result.grade,
                findings_critical=summary.get('critical', 0),
                findings_high=summary.get('high', 0),
                findings_medium=summary.get('medium', 0),
                findings_low=summary.get('low', 0),
                findings_info=summary.get('info', 0),
                findings_total=len(scan_result.findings),
                findings=[f.to_dict() for f in scan_result.findings],
                ssl_info=scan_result.ssl_info,
                headers_info=scan_result.headers_info,
                dns_info=scan_result.dns_info,
                whois_info=scan_result.whois_info,
                technology_info=scan_result.technology_info,
                breach_info=scan_result.breach_info,
                port_info=getattr(scan_result, 'port_info', {}),
                scan_duration_ms=scan_result.scan_duration_ms,
                scan_source=scan_source,
            )
            session.add(record)
            session.flush()  # get record.id before commit

            # Auto-set IDS baseline on first scan
            domain_obj = session.query(MonitoredDomain).filter(
                MonitoredDomain.id == monitored_domain_id
            ).first()
            if domain_obj and domain_obj.baseline_set_at is None:
                _set_baseline(domain_obj, scan_result)

            # Update the monitored domain's latest score (within same session)
            if domain_obj:
                domain_obj.previous_score = domain_obj.latest_score
                domain_obj.latest_score = scan_result.score
                domain_obj.latest_grade = scan_result.grade
                domain_obj.latest_scan_at = datetime.utcnow()

            session.commit()
            return record.id
        finally:
            session.close()

    def get_scan_history(self, monitored_domain_id: int, limit: int = 30) -> List[Dict]:
        """Get scan history for a domain"""
        session = self.get_session()
        try:
            records = session.query(DomainScanRecord).filter(
                DomainScanRecord.monitored_domain_id == monitored_domain_id
            ).order_by(DomainScanRecord.created_at.desc()).limit(limit).all()
            return [r.to_dict() for r in records]
        finally:
            session.close()

    def get_latest_scan(self, monitored_domain_id: int) -> Optional[Dict]:
        """Get the most recent scan for a domain"""
        session = self.get_session()
        try:
            record = session.query(DomainScanRecord).filter(
                DomainScanRecord.monitored_domain_id == monitored_domain_id
            ).order_by(DomainScanRecord.created_at.desc()).first()
            return record.to_dict() if record else None
        finally:
            session.close()

    def get_score_trend(self, monitored_domain_id: int, days: int = 30) -> List[Dict]:
        """Get score trend data for charting"""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(days=days)
            records = session.query(
                DomainScanRecord.score,
                DomainScanRecord.grade,
                DomainScanRecord.findings_total,
                DomainScanRecord.created_at
            ).filter(
                DomainScanRecord.monitored_domain_id == monitored_domain_id,
                DomainScanRecord.created_at >= since
            ).order_by(DomainScanRecord.created_at.asc()).all()

            return [{
                'score': r.score,
                'grade': r.grade,
                'findings': r.findings_total,
                'date': r.created_at.isoformat()
            } for r in records]
        finally:
            session.close()

    # ---------- Alerts ----------

    def create_alert(self, monitored_domain_id: int, user_id: int,
                     alert_type: str, title: str, message: str,
                     severity: str = 'medium', alert_rule_id: int = None) -> int:
        """Create a new alert"""
        session = self.get_session()
        try:
            alert = DomainAlert(
                monitored_domain_id=monitored_domain_id,
                alert_rule_id=alert_rule_id,
                user_id=user_id,
                alert_type=alert_type,
                title=title,
                message=message,
                severity=severity,
            )
            session.add(alert)
            session.commit()
            return alert.id
        finally:
            session.close()

    def get_user_alerts(self, user_id: int, unread_only: bool = False, limit: int = 50) -> List[Dict]:
        """Get alerts for a user"""
        session = self.get_session()
        try:
            query = session.query(DomainAlert).filter(DomainAlert.user_id == user_id)
            if unread_only:
                query = query.filter(DomainAlert.is_read == False)
            alerts = query.order_by(DomainAlert.created_at.desc()).limit(limit).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()

    def mark_alert_read(self, alert_id: int, user_id: int) -> bool:
        """Mark an alert as read"""
        session = self.get_session()
        try:
            alert = session.query(DomainAlert).filter(
                DomainAlert.id == alert_id,
                DomainAlert.user_id == user_id
            ).first()
            if alert:
                alert.is_read = True
                alert.read_at = datetime.utcnow()
                session.commit()
                return True
            return False
        finally:
            session.close()

    def get_unread_alert_count(self, user_id: int) -> int:
        """Get count of unread alerts"""
        session = self.get_session()
        try:
            return session.query(DomainAlert).filter(
                DomainAlert.user_id == user_id,
                DomainAlert.is_read == False
            ).count()
        finally:
            session.close()

    # ---------- IDS ----------

    def get_ids_alerts(self, domain_id: int, limit: int = 20) -> List[Dict]:
        """Return IDS-specific alerts for a monitored domain."""
        IDS_TYPES = ('new_port_detected', 'ssl_cert_changed', 'dns_record_changed', 'content_changed')
        session = self.get_session()
        try:
            alerts = session.query(DomainAlert).filter(
                DomainAlert.monitored_domain_id == domain_id,
                DomainAlert.alert_type.in_(IDS_TYPES)
            ).order_by(DomainAlert.created_at.desc()).limit(limit).all()
            return [a.to_dict() for a in alerts]
        finally:
            session.close()

    def has_recent_ids_alert(self, domain_id: int, alert_type: str,
                             title_fragment: str, hours: int = 24) -> bool:
        """Return True if a matching IDS alert was already fired within `hours`."""
        session = self.get_session()
        try:
            since = datetime.utcnow() - timedelta(hours=hours)
            return session.query(DomainAlert).filter(
                DomainAlert.monitored_domain_id == domain_id,
                DomainAlert.alert_type == alert_type,
                DomainAlert.title.contains(title_fragment),
                DomainAlert.created_at >= since
            ).first() is not None
        finally:
            session.close()

    def reset_baseline_from_scan_record(self, domain_id: int, user_id: int,
                                        scan_dict: Dict) -> Optional[Dict]:
        """Reset IDS baseline from a saved scan record dict. Returns updated domain dict."""
        session = self.get_session()
        try:
            domain_obj = session.query(MonitoredDomain).filter(
                MonitoredDomain.id == domain_id,
                MonitoredDomain.user_id == user_id
            ).first()
            if not domain_obj:
                return None

            ssl_info = scan_dict.get('ssl_info') or {}
            dns_info = scan_dict.get('dns_info') or {}
            port_info = scan_dict.get('port_info') or {}

            def _extract(records, key='host'):
                out = []
                for r in (records or []):
                    out.append(r[key] if isinstance(r, dict) else str(r))
                return out

            domain_obj.baseline_ports = port_info.get('open_ports', [])
            domain_obj.baseline_ssl_fingerprint = ssl_info.get('fingerprint')
            domain_obj.baseline_ssl_issuer = ssl_info.get('issuer')
            domain_obj.baseline_dns = {
                'A':   [r if isinstance(r, str) else r.get('address', str(r))
                        for r in dns_info.get('a_records', [])],
                'MX':  _extract(dns_info.get('mx_records', []), 'host'),
                'NS':  _extract(dns_info.get('ns_records', []), 'host'),
                'TXT': [r if isinstance(r, str) else r.get('text', str(r))
                        for r in dns_info.get('txt_records', [])],
            }
            # content_hash is re-established on the next live scan
            domain_obj.baseline_content_hash = None
            domain_obj.baseline_set_at = datetime.utcnow()
            session.commit()
            return domain_obj.to_dict()
        finally:
            session.close()

    # ---------- Dashboard Stats ----------

    def get_dashboard_stats(self, user_id: int) -> Dict:
        """Get summary stats for the monitoring dashboard"""
        session = self.get_session()
        try:
            domains = session.query(MonitoredDomain).filter(
                MonitoredDomain.user_id == user_id,
                MonitoredDomain.is_active == True
            ).all()

            total_domains = len(domains)
            scores = [d.latest_score for d in domains if d.latest_score is not None]
            avg_score = round(sum(scores) / len(scores), 1) if scores else None

            grade_counts = {}
            for d in domains:
                g = d.latest_grade or 'N/A'
                grade_counts[g] = grade_counts.get(g, 0) + 1

            # Count recent findings across all domains
            recent_scans = session.query(DomainScanRecord).filter(
                DomainScanRecord.user_id == user_id,
                DomainScanRecord.created_at >= datetime.utcnow() - timedelta(days=7)
            ).all()

            total_findings = sum(s.findings_total for s in recent_scans)
            critical_findings = sum(s.findings_critical for s in recent_scans)

            unread_alerts = session.query(DomainAlert).filter(
                DomainAlert.user_id == user_id,
                DomainAlert.is_read == False
            ).count()

            IDS_TYPES = ('new_port_detected', 'ssl_cert_changed', 'dns_record_changed', 'content_changed')
            ids_alert_count = session.query(DomainAlert).filter(
                DomainAlert.user_id == user_id,
                DomainAlert.is_read == False,
                DomainAlert.alert_type.in_(IDS_TYPES)
            ).count()

            return {
                'total_domains': total_domains,
                'average_score': avg_score,
                'grade_distribution': grade_counts,
                'findings_last_7_days': total_findings,
                'critical_findings_last_7_days': critical_findings,
                'unread_alerts': unread_alerts,
                'ids_alert_count': ids_alert_count,
                'domains': [d.to_dict() for d in domains],
            }
        finally:
            session.close()
