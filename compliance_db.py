"""
Security Compliance Center - Database Models & Logic
Tracks compliance checklist progress, generates policy templates,
and calculates a compliance readiness score.

Copyright (c) 2026 SecureLink. All rights reserved.
"""
from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy import (
    create_engine, Column, Integer, String, Boolean,
    DateTime, Text, JSON, ForeignKey
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

from config import Config

Base = declarative_base()


# ============================================================
#  Database Model
# ============================================================

class ComplianceCheckStatus(Base):
    """Tracks which compliance controls a user has completed."""
    __tablename__ = 'compliance_check_status'

    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, nullable=False, index=True)
    check_id = Column(String(80), nullable=False, index=True)   # e.g. "soc2_cc6.1_mfa"
    is_completed = Column(Boolean, default=False)
    completed_at = Column(DateTime, nullable=True)
    notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================
#  Compliance Framework definitions  (static data)
# ============================================================

FRAMEWORKS = {
    'soc2': {
        'id': 'soc2',
        'name': 'SOC 2 Type II',
        'description': 'Service Organization Control 2 — Trust Services Criteria',
        'icon': 'bi-shield-check',
    },
    'iso27001': {
        'id': 'iso27001',
        'name': 'ISO 27001',
        'description': 'Information Security Management System (ISMS)',
        'icon': 'bi-patch-check',
    },
    'gdpr': {
        'id': 'gdpr',
        'name': 'GDPR',
        'description': 'General Data Protection Regulation (EU)',
        'icon': 'bi-globe-europe-africa',
    },
}

# Each check maps to one or more frameworks.
# "auto_source" means SecureLink can verify it automatically.
COMPLIANCE_CHECKS: List[Dict] = [
    # ── Access Control ──────────────────────────────────────
    {
        'id': 'access_strong_password',
        'title': 'Enforce strong password policy',
        'description': 'Require passwords with minimum 12 characters, including uppercase, lowercase, numbers, and special characters.',
        'category': 'Access Control',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'easy',
        'auto_source': None,
    },
    {
        'id': 'access_mfa',
        'title': 'Enable multi-factor authentication (MFA)',
        'description': 'Require a second authentication factor for all user accounts to prevent unauthorized access.',
        'category': 'Access Control',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'access_session_timeout',
        'title': 'Set session inactivity timeout',
        'description': 'Automatically sign users out after 30 minutes of inactivity.',
        'category': 'Access Control',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': 'session_timeout',
    },
    {
        'id': 'access_rbac',
        'title': 'Implement role-based access control',
        'description': 'Assign users the minimum permissions necessary to perform their duties (principle of least privilege).',
        'category': 'Access Control',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'access_account_lockout',
        'title': 'Enable account lockout on failed logins',
        'description': 'Temporarily lock accounts after repeated failed login attempts to prevent brute-force attacks.',
        'category': 'Access Control',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': 'account_lockout',
    },

    # ── Data Protection ─────────────────────────────────────
    {
        'id': 'data_encryption_transit',
        'title': 'Encrypt data in transit (HTTPS/TLS)',
        'description': 'Ensure all web traffic uses HTTPS with modern TLS (1.2+). Verify via Attack Surface Monitor.',
        'category': 'Data Protection',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'easy',
        'auto_source': 'attack_surface_ssl',
    },
    {
        'id': 'data_encryption_rest',
        'title': 'Encrypt sensitive data at rest',
        'description': 'Use AES-256 or equivalent encryption for databases, backups, and stored credentials.',
        'category': 'Data Protection',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'data_backup',
        'title': 'Maintain regular encrypted backups',
        'description': 'Perform automated daily backups with encryption and test restores quarterly.',
        'category': 'Data Protection',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'data_retention',
        'title': 'Define a data retention policy',
        'description': 'Document how long each category of data is kept and when it is securely deleted.',
        'category': 'Data Protection',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'data_privacy_policy',
        'title': 'Publish a privacy policy',
        'description': 'Maintain a public privacy policy that explains what data you collect, how you use it, and user rights.',
        'category': 'Data Protection',
        'frameworks': ['gdpr'],
        'difficulty': 'easy',
        'auto_source': None,
    },

    # ── Monitoring & Detection ──────────────────────────────
    {
        'id': 'monitor_dark_web',
        'title': 'Enable dark web monitoring',
        'description': 'Monitor for leaked credentials and sensitive company data on the dark web.',
        'category': 'Monitoring & Detection',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': 'dark_web_monitoring',
    },
    {
        'id': 'monitor_attack_surface',
        'title': 'Enable attack surface monitoring',
        'description': 'Continuously scan public-facing domains for vulnerabilities, misconfigurations, and exposures.',
        'category': 'Monitoring & Detection',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': 'attack_surface',
    },
    {
        'id': 'monitor_security_headers',
        'title': 'Implement security headers',
        'description': 'Deploy Content-Security-Policy, X-Frame-Options, HSTS, and other protective HTTP headers.',
        'category': 'Monitoring & Detection',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'medium',
        'auto_source': 'attack_surface_headers',
    },
    {
        'id': 'monitor_logging',
        'title': 'Enable centralized audit logging',
        'description': 'Collect and retain security-relevant logs (logins, permission changes, data access) for at least 90 days.',
        'category': 'Monitoring & Detection',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'monitor_link_scanning',
        'title': 'Scan links for phishing & malware',
        'description': 'Use SecureLink to scan URLs shared within your organization for threats before employees click them.',
        'category': 'Monitoring & Detection',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': 'link_scanning',
    },

    # ── Policies & Governance ───────────────────────────────
    {
        'id': 'policy_acceptable_use',
        'title': 'Create an Acceptable Use Policy',
        'description': 'Document rules for how employees may use company systems, networks, and data.',
        'category': 'Policies & Governance',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': None,
    },
    {
        'id': 'policy_incident_response',
        'title': 'Create an Incident Response Plan',
        'description': 'Document step-by-step procedures for detecting, containing, and recovering from security incidents.',
        'category': 'Policies & Governance',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'policy_vendor_management',
        'title': 'Create a Vendor Management Policy',
        'description': 'Evaluate and document the security posture of third-party vendors and service providers.',
        'category': 'Policies & Governance',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'policy_change_management',
        'title': 'Create a Change Management Policy',
        'description': 'Define a process for reviewing, approving, and documenting changes to systems and infrastructure.',
        'category': 'Policies & Governance',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'medium',
        'auto_source': None,
    },

    # ── People & Awareness ──────────────────────────────────
    {
        'id': 'people_security_training',
        'title': 'Conduct security awareness training',
        'description': 'Train employees on phishing identification, password hygiene, and secure data handling at least annually.',
        'category': 'People & Awareness',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'medium',
        'auto_source': None,
    },
    {
        'id': 'people_onboarding_offboarding',
        'title': 'Security onboarding & offboarding process',
        'description': 'Ensure new employees receive security orientation and departing employees have access revoked immediately.',
        'category': 'People & Awareness',
        'frameworks': ['soc2', 'iso27001'],
        'difficulty': 'easy',
        'auto_source': None,
    },
    {
        'id': 'people_designated_owner',
        'title': 'Designate a security owner',
        'description': 'Assign a specific person (e.g., CTO, CISO) as accountable for information security.',
        'category': 'People & Awareness',
        'frameworks': ['soc2', 'iso27001', 'gdpr'],
        'difficulty': 'easy',
        'auto_source': None,
    },
]

# -- Category order for display --
CATEGORY_ORDER = [
    'Access Control',
    'Data Protection',
    'Monitoring & Detection',
    'Policies & Governance',
    'People & Awareness',
]


# ============================================================
#  Policy Templates (markdown text)
# ============================================================

POLICY_TEMPLATES = {
    'acceptable_use': {
        'title': 'Acceptable Use Policy',
        'filename': 'Acceptable_Use_Policy.md',
        'icon': 'bi-file-earmark-text',
        'content': """# Acceptable Use Policy

**Company:** {company_name}
**Effective Date:** {date}
**Version:** 1.0

## 1. Purpose
This policy establishes acceptable and unacceptable uses of {company_name}'s electronic systems, devices, and networks to protect the organization from security risks.

## 2. Scope
This policy applies to all employees, contractors, consultants, and third parties who access {company_name}'s systems.

## 3. Acceptable Use
- Use company systems for authorized business purposes.
- Protect login credentials and do not share passwords.
- Lock your workstation when stepping away.
- Report suspected security incidents immediately.

## 4. Prohibited Use
- Sharing company credentials with unauthorized parties.
- Installing unauthorized software on company devices.
- Accessing or distributing offensive, illegal, or pirated material.
- Bypassing security controls such as firewalls or anti-virus software.
- Using company email for personal mass mailings or chain letters.

## 5. Internet & Email
- Exercise caution when clicking links in emails. Use SecureLink or similar tools to verify URLs.
- Do not send sensitive data via unencrypted email.
- Avoid connecting to untrusted Wi-Fi networks without a VPN.

## 6. Enforcement
Violations of this policy may result in disciplinary action, up to and including termination and legal action. Suspected violations should be reported to the designated security owner.

## 7. Review
This policy will be reviewed annually and updated as needed.

---
*Generated by SecureLink Compliance Center*
""",
    },
    'incident_response': {
        'title': 'Incident Response Plan',
        'filename': 'Incident_Response_Plan.md',
        'icon': 'bi-exclamation-triangle',
        'content': """# Incident Response Plan

**Company:** {company_name}
**Effective Date:** {date}
**Version:** 1.0

## 1. Purpose
This plan provides a structured approach for responding to information security incidents to minimize impact and recover quickly.

## 2. Incident Classification
| Severity | Description | Response Time |
|----------|-------------|---------------|
| Critical | Data breach, ransomware, system compromise | Within 1 hour |
| High | Unauthorized access attempt, malware detection | Within 4 hours |
| Medium | Phishing email, suspicious activity | Within 24 hours |
| Low | Policy violation, failed login anomalies | Within 72 hours |

## 3. Incident Response Team
| Role | Responsibility |
|------|---------------|
| Incident Commander | Coordinates response activities |
| Technical Lead | Investigates and contains the incident |
| Communications Lead | Manages internal/external communications |
| Legal / Compliance | Assesses regulatory notification requirements |

## 4. Response Phases

### 4.1 Detection & Identification
- Monitor SecureLink dark web alerts, attack surface findings, and link scan results.
- Investigate alerts and determine if a real incident has occurred.
- Document the incident in the incident log.

### 4.2 Containment
- Isolate affected systems from the network.
- Revoke compromised credentials immediately.
- Preserve forensic evidence (logs, disk images).

### 4.3 Eradication
- Remove malware, unauthorized access, or vulnerable components.
- Patch exploited vulnerabilities.

### 4.4 Recovery
- Restore systems from clean backups.
- Monitor restored systems closely for 72 hours.
- Confirm normal operations.

### 4.5 Post-Incident Review
- Conduct a lessons-learned meeting within 5 business days.
- Update policies, procedures, and controls as needed.
- File any required regulatory notifications (e.g., GDPR 72-hour rule).

## 5. Communication Templates
- Internal stakeholder notification
- Customer notification (if data was affected)
- Regulatory authority notification (GDPR Art. 33)

## 6. Review
This plan will be tested via tabletop exercises at least annually.

---
*Generated by SecureLink Compliance Center*
""",
    },
    'data_retention': {
        'title': 'Data Retention Policy',
        'filename': 'Data_Retention_Policy.md',
        'icon': 'bi-database',
        'content': """# Data Retention Policy

**Company:** {company_name}
**Effective Date:** {date}
**Version:** 1.0

## 1. Purpose
This policy defines how long {company_name} retains different categories of data and the procedures for secure deletion.

## 2. Scope
Applies to all data collected, processed, or stored by {company_name}, whether in digital or physical form.

## 3. Retention Schedule

| Data Category | Retention Period | Deletion Method |
|---------------|-----------------|-----------------|
| User account data | Duration of account + 30 days | Automated purge |
| Authentication logs | 1 year | Automated rotation |
| Transaction records | 7 years (legal requirement) | Secure deletion |
| Support tickets | 2 years after resolution | Automated purge |
| Marketing consent records | Duration of consent + 3 years | Manual review |
| Employee records | Duration of employment + 7 years | Secure shredding / deletion |
| Backup data | 90 days rolling | Automated overwrite |
| Security scan results | 1 year | Automated purge |

## 4. Secure Deletion Methods
- **Digital data:** Overwrite with random data or use cryptographic erasure.
- **Physical media:** Cross-cut shredding or degaussing.
- **Cloud data:** Verify deletion through provider's data destruction certificate.

## 5. Exceptions
Data subject to legal hold, regulatory investigation, or active litigation must be preserved until the hold is lifted, regardless of the retention schedule.

## 6. User Data Rights (GDPR)
- Users may request a copy of their data (Right of Access).
- Users may request deletion of their data (Right to Erasure).
- Requests must be fulfilled within 30 days.

## 7. Review
This policy will be reviewed annually.

---
*Generated by SecureLink Compliance Center*
""",
    },
    'access_control': {
        'title': 'Access Control Policy',
        'filename': 'Access_Control_Policy.md',
        'icon': 'bi-key',
        'content': """# Access Control Policy

**Company:** {company_name}
**Effective Date:** {date}
**Version:** 1.0

## 1. Purpose
This policy establishes requirements for controlling access to {company_name}'s information systems and data, based on the principle of least privilege.

## 2. Scope
All employees, contractors, and third-party users who access company systems.

## 3. Authentication Requirements
- **Passwords:** Minimum 12 characters, with complexity requirements (upper, lower, number, special character).
- **Multi-Factor Authentication:** Required for all accounts with access to production systems, customer data, or admin panels.
- **Session Timeout:** Sessions must automatically expire after 30 minutes of inactivity.
- **Account Lockout:** Accounts are locked after 5 consecutive failed login attempts.

## 4. Authorization
- Access is granted on a need-to-know, least-privilege basis.
- Role-based access control (RBAC) is used to assign permissions.
- Admin/root access is limited to designated personnel and requires MFA.
- Access rights are reviewed quarterly.

## 5. Account Lifecycle
| Event | Action | Timeline |
|-------|--------|----------|
| New hire | Create account with role-based permissions | Day 1 |
| Role change | Adjust permissions to match new role | Within 24 hours |
| Termination | Disable account, revoke all access | Immediately |
| Extended leave | Temporarily disable account | Before leave starts |

## 6. Remote Access
- VPN or zero-trust network access required for remote connections.
- Personal devices must meet minimum security standards (encryption, up-to-date OS).

## 7. Monitoring
- All access to sensitive systems is logged.
- Logs are reviewed regularly for anomalies.
- SecureLink's dark web monitoring detects leaked credentials.

## 8. Review
This policy will be reviewed annually and updated as needed.

---
*Generated by SecureLink Compliance Center*
""",
    },
}


# ============================================================
#  Database Access Layer
# ============================================================

class ComplianceDB:
    """Handles all compliance-related database operations."""

    def __init__(self, config: Config = None):
        self.config = config or Config()
        from db_engine import get_database_engine, safe_create_tables
        self.engine = get_database_engine(self.config)
        safe_create_tables(Base.metadata, self.engine)
        self.Session = sessionmaker(bind=self.engine)

    # ---------- helpers ----------

    def _session(self):
        return self.Session()

    # ---------- check status CRUD ----------

    def get_user_checks(self, user_id: int) -> Dict[str, dict]:
        """Return a dict of check_id -> {is_completed, completed_at, notes}"""
        session = self._session()
        try:
            rows = session.query(ComplianceCheckStatus).filter(
                ComplianceCheckStatus.user_id == user_id
            ).all()
            return {
                r.check_id: {
                    'is_completed': r.is_completed,
                    'completed_at': r.completed_at.isoformat() if r.completed_at else None,
                    'notes': r.notes,
                }
                for r in rows
            }
        finally:
            session.close()

    def toggle_check(self, user_id: int, check_id: str, completed: bool, notes: str = None) -> dict:
        """Mark a check as completed or uncompleted."""
        session = self._session()
        try:
            row = session.query(ComplianceCheckStatus).filter(
                ComplianceCheckStatus.user_id == user_id,
                ComplianceCheckStatus.check_id == check_id,
            ).first()

            if not row:
                row = ComplianceCheckStatus(user_id=user_id, check_id=check_id)
                session.add(row)

            row.is_completed = completed
            row.completed_at = datetime.utcnow() if completed else None
            if notes is not None:
                row.notes = notes
            row.updated_at = datetime.utcnow()

            session.commit()
            return {
                'check_id': check_id,
                'is_completed': row.is_completed,
                'completed_at': row.completed_at.isoformat() if row.completed_at else None,
            }
        except Exception as e:
            session.rollback()
            raise
        finally:
            session.close()

    # ---------- scoring ----------

    def compute_score(self, user_id: int, framework: str = None) -> dict:
        """Compute % compliance score, optionally filtered by framework."""
        user_statuses = self.get_user_checks(user_id)

        checks = COMPLIANCE_CHECKS
        if framework and framework in FRAMEWORKS:
            checks = [c for c in checks if framework in c['frameworks']]

        total = len(checks)
        if total == 0:
            return {'score': 0, 'completed': 0, 'total': 0, 'grade': 'N/A'}

        completed = sum(
            1 for c in checks
            if user_statuses.get(c['id'], {}).get('is_completed', False)
        )

        pct = round(completed / total * 100)
        grade = (
            'A' if pct >= 90 else
            'B' if pct >= 75 else
            'C' if pct >= 60 else
            'D' if pct >= 40 else
            'F'
        )

        return {
            'score': pct,
            'completed': completed,
            'total': total,
            'grade': grade,
            'framework': framework,
        }

    def compute_category_scores(self, user_id: int) -> List[dict]:
        """Compute score per category."""
        user_statuses = self.get_user_checks(user_id)
        result = []
        for cat in CATEGORY_ORDER:
            checks = [c for c in COMPLIANCE_CHECKS if c['category'] == cat]
            total = len(checks)
            done = sum(
                1 for c in checks
                if user_statuses.get(c['id'], {}).get('is_completed', False)
            )
            result.append({
                'category': cat,
                'completed': done,
                'total': total,
                'score': round(done / total * 100) if total else 0,
            })
        return result
