from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from sqlalchemy import (
    Boolean,
    BigInteger,
    CheckConstraint,
    DateTime,
    ForeignKey,
    ForeignKeyConstraint,
    Index,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    Uuid,
    func,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "users"
    __table_args__ = (UniqueConstraint("email_normalized", name="uq_users_email_normalized"),)

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    email: Mapped[str] = mapped_column(String(320), nullable=False)
    email_normalized: Mapped[str] = mapped_column(String(320), nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=True, nullable=False)
    email_verified: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    invitation_setup_required: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("false"), nullable=False
    )
    token_version: Mapped[int] = mapped_column(
        Integer, default=0, server_default=text("0"), nullable=False
    )
    mfa_secret_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    mfa_enrollment_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_rotation_secret_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    mfa_rotation_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    mfa_last_totp_step: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    privileged_mfa_grace_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    memberships: Mapped[list[Membership]] = relationship(back_populates="user")


class Organization(Base):
    __tablename__ = "organizations"

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    memberships: Mapped[list[Membership]] = relationship(back_populates="organization")


class DomainAsset(Base):
    __tablename__ = "domain_assets"
    __table_args__ = (
        UniqueConstraint("organization_id", "hostname", name="uq_domain_assets_org_hostname"),
        UniqueConstraint("id", "organization_id", name="uq_domain_assets_id_organization"),
        CheckConstraint("status IN ('pending', 'verified')", name="ck_domain_assets_status"),
        CheckConstraint(
            "(status = 'pending' AND verification_token_hash IS NOT NULL "
            "AND verification_expires_at IS NOT NULL AND verified_at IS NULL) OR "
            "(status = 'verified' AND verification_token_hash IS NULL "
            "AND verification_expires_at IS NULL AND verified_at IS NOT NULL)",
            name="ck_domain_assets_verification_state",
        ),
        Index("ix_domain_assets_org_status", "organization_id", "status"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    status: Mapped[str] = mapped_column(String(12), default="pending", server_default="pending", nullable=False)
    monitoring_enabled: Mapped[bool] = mapped_column(Boolean, default=False, server_default=text("false"), nullable=False)
    verification_token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    verification_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), nullable=False
    )


class ThreatIndicator(Base):
    """Organization-managed exact-host indicators; no external feed implied."""

    __tablename__ = "threat_indicators"
    __table_args__ = (
        UniqueConstraint("organization_id", "hostname", name="uq_threat_indicators_org_hostname"),
        CheckConstraint("source = 'customer'", name="ck_threat_indicators_source"),
        Index("ix_threat_indicators_org_hostname", "organization_id", "hostname"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    source: Mapped[str] = mapped_column(String(16), default="customer", server_default="customer", nullable=False)
    note: Mapped[str | None] = mapped_column(String(240), nullable=True)
    created_by_user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="RESTRICT"), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class DomainMonitorState(Base):
    __tablename__ = "domain_monitor_states"
    __table_args__ = (
        ForeignKeyConstraint(
            ["asset_id", "organization_id"],
            ["domain_assets.id", "domain_assets.organization_id"],
            name="fk_domain_monitor_states_asset_organization",
            ondelete="CASCADE",
        ),
        CheckConstraint("generation >= 0", name="ck_domain_monitor_states_generation"),
        Index("ix_domain_monitor_states_due", "next_check_at", "lease_until"),
    )

    asset_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True)
    organization_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True)
    monitor_type: Mapped[str] = mapped_column(String(64), primary_key=True)
    current_state: Mapped[str] = mapped_column(Text, default="{}", server_default="{}", nullable=False)
    generation: Mapped[int] = mapped_column(Integer, default=0, server_default="0", nullable=False)
    last_checked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    next_check_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(64), nullable=True)


class Membership(Base):
    __tablename__ = "memberships"
    __table_args__ = (
        UniqueConstraint("organization_id", "user_id", name="uq_memberships_org_user"),
        CheckConstraint("role IN ('owner', 'admin', 'analyst', 'viewer')", name="ck_memberships_role"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False, index=True
    )
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False)
    priority_email_enabled: Mapped[bool] = mapped_column(
        Boolean, default=True, server_default=text("true"), nullable=False
    )
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    organization: Mapped[Organization] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship(back_populates="memberships")


class AuditEvent(Base):
    __tablename__ = "audit_events"
    __table_args__ = (
        CheckConstraint("action <> ''", name="ck_audit_events_action_nonempty"),
        CheckConstraint("actor_type IN ('user', 'system')", name="ck_audit_events_actor_type"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str | None] = mapped_column(
        ForeignKey("organizations.id", ondelete="RESTRICT"), nullable=True, index=True
    )
    actor_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    actor_type: Mapped[str] = mapped_column(String(8), nullable=False)
    action: Mapped[str] = mapped_column(String(120), nullable=False)
    target_type: Mapped[str] = mapped_column(String(120), nullable=False)
    target_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    details: Mapped[str] = mapped_column(Text, default="{}", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)

class EmailActionToken(Base):
    __tablename__ = "email_action_tokens"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('verify_email', 'reset_password', 'invite_member')",
            name="ck_email_action_tokens_purpose",
        ),
        UniqueConstraint("token_hash", name="uq_email_action_tokens_hash"),
        CheckConstraint(
            "delivery_state IN ('pending', 'sending', 'sent', 'failed', 'cancelled')",
            name="ck_email_action_tokens_delivery_state",
        ),
        CheckConstraint("requested_role IS NULL OR requested_role IN ('owner', 'admin', 'analyst', 'viewer')", name="ck_email_action_tokens_requested_role"),
        Index("ix_email_action_tokens_delivery", "delivery_state", "next_delivery_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    purpose: Mapped[str] = mapped_column(String(24), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    organization_id: Mapped[str | None] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=True, index=True)
    requested_role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    delivery_ciphertext: Mapped[bytes | None] = mapped_column(LargeBinary, nullable=True)
    delivery_state: Mapped[str] = mapped_column(
        String(12), default="pending", server_default="pending", nullable=False
    )
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    next_delivery_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), nullable=False
    )
    delivery_lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_delivery_error: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class MFARecoveryCode(Base):
    __tablename__ = "mfa_recovery_codes"
    __table_args__ = (
        UniqueConstraint("user_id", "code_hash", name="uq_mfa_recovery_codes_user_hash"),
        Index("ix_mfa_recovery_codes_user_unused", "user_id", "consumed_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class SecurityNotificationOutbox(Base):
    __tablename__ = "security_notification_outbox"
    __table_args__ = (
        UniqueConstraint("case_id", "user_id", name="uq_security_notification_case_user"),
        CheckConstraint(
            "delivery_state IN ('pending', 'sending', 'sent', 'failed', 'cancelled')",
            name="ck_security_notification_delivery_state",
        ),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_security_notification_case_organization",
            ondelete="CASCADE",
        ),
        Index("ix_security_notification_delivery", "delivery_state", "next_delivery_at"),
        Index("ix_security_notification_org_state_created", "organization_id", "delivery_state", "created_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    delivery_state: Mapped[str] = mapped_column(String(12), default="pending", server_default="pending", nullable=False)
    delivery_attempts: Mapped[int] = mapped_column(Integer, default=0, server_default=text("0"), nullable=False)
    next_delivery_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), nullable=False
    )
    delivery_lease_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_delivery_error: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class ExtensionAuthorizationCode(Base):
    __tablename__ = "extension_authorization_codes"
    __table_args__ = (
        UniqueConstraint("code_hash", name="uq_extension_authorization_codes_hash"),
        Index("ix_extension_authorization_codes_expiry", "expires_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    code_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    client_id: Mapped[str] = mapped_column(String(64), nullable=False)
    redirect_uri: Mapped[str] = mapped_column(String(512), nullable=False)
    code_challenge: Mapped[str] = mapped_column(String(128), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    token_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class ExtensionSession(Base):
    __tablename__ = "extension_sessions"
    __table_args__ = (
        UniqueConstraint("token_hash", name="uq_extension_sessions_token_hash"),
        Index("ix_extension_sessions_user_org", "user_id", "organization_id"),
        Index("ix_extension_sessions_expiry", "expires_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    user_id: Mapped[str] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    token_version: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )


class UrlScan(Base):
    __tablename__ = "url_scans"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_url_scans_id_organization"),
        CheckConstraint("status = 'completed'", name="ck_url_scans_status"),
        Index("ix_url_scans_organization_created", "organization_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    requested_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    display_url: Mapped[str] = mapped_column(String(512), nullable=False)
    hostname: Mapped[str] = mapped_column(String(253), nullable=False)
    scheme: Mapped[str] = mapped_column(String(5), nullable=False)
    status: Mapped[str] = mapped_column(String(16), default="completed", nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class ScanEvidence(Base):
    __tablename__ = "scan_evidence"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_scan_evidence_id_organization"),
        ForeignKeyConstraint(
            ["scan_id", "organization_id"],
            ["url_scans.id", "url_scans.organization_id"],
            name="fk_scan_evidence_scan_organization",
            ondelete="CASCADE",
        ),
        Index("ix_scan_evidence_scan", "scan_id"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    source_type: Mapped[str] = mapped_column(String(32), nullable=False)
    detector_version: Mapped[str] = mapped_column(String(32), nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class Finding(Base):
    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_findings_id_organization"),
        ForeignKeyConstraint(
            ["scan_id", "organization_id"],
            ["url_scans.id", "url_scans.organization_id"],
            name="fk_findings_scan_organization",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["evidence_id", "organization_id"],
            ["scan_evidence.id", "scan_evidence.organization_id"],
            name="fk_findings_evidence_organization",
            ondelete="RESTRICT",
        ),
        UniqueConstraint("scan_id", "detector_code", name="uq_findings_scan_detector"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_findings_severity",
        ),
        Index("ix_findings_organization_created", "organization_id", "created_at"),
        Index("ix_findings_scan", "scan_id"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    scan_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    evidence_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    detector_code: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(160), nullable=False)
    description: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)


class SecuritySignal(Base):
    __tablename__ = "security_signals"
    __table_args__ = (
        UniqueConstraint("organization_id", "source_type", "source_reference", name="uq_security_signal_source"),
        UniqueConstraint("id", "organization_id", name="uq_security_signals_id_organization"),
        CheckConstraint(
            "source_type IN ('url_scan', 'extension_scan', 'domain_monitor', 'integration')",
            name="ck_security_signals_source_type",
        ),
        CheckConstraint("signal_type <> ''", name="ck_security_signals_type_nonempty"),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_security_signals_severity",
        ),
        Index("ix_security_signals_org_observed", "organization_id", "observed_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    source_type: Mapped[str] = mapped_column(String(24), nullable=False)
    source_reference: Mapped[str] = mapped_column(String(128), nullable=False)
    signal_type: Mapped[str] = mapped_column(String(64), nullable=False)
    subject: Mapped[str] = mapped_column(String(253), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    observed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    payload: Mapped[str] = mapped_column(Text, nullable=False)
    content_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class IncidentCase(Base):
    __tablename__ = "incident_cases"
    __table_args__ = (
        UniqueConstraint("id", "organization_id", name="uq_incident_cases_id_organization"),
        UniqueConstraint("scan_id", "organization_id", name="uq_incident_cases_scan_organization"),
        CheckConstraint(
            "status IN ('open', 'investigating', 'awaiting_approval', 'resolved', 'false_positive')",
            name="ck_incident_cases_status",
        ),
        CheckConstraint(
            "severity IN ('critical', 'high', 'medium', 'low', 'informational')",
            name="ck_incident_cases_severity",
        ),
        Index("ix_incident_cases_org_status_created", "organization_id", "status", "created_at"),
        ForeignKeyConstraint(
            ["scan_id", "organization_id"],
            ["url_scans.id", "url_scans.organization_id"],
            name="fk_incident_cases_scan_organization",
            ondelete="CASCADE",
        ),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False
    )
    scan_id: Mapped[str | None] = mapped_column(Uuid(as_uuid=False), nullable=True)
    created_by_user_id: Mapped[str | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(24), default="open", server_default="open", nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    title: Mapped[str] = mapped_column(String(200), nullable=False)
    summary: Mapped[str] = mapped_column(String(512), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, server_default=func.now(), onupdate=utc_now, nullable=False
    )
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CaseSignal(Base):
    __tablename__ = "case_signals"
    __table_args__ = (
        UniqueConstraint("case_id", "signal_id", name="uq_case_signals_case_signal"),
        UniqueConstraint("signal_id", "organization_id", name="uq_case_signals_signal_organization"),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_signals_case_organization",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["signal_id", "organization_id"],
            ["security_signals.id", "security_signals.organization_id"],
            name="fk_case_signals_signal_organization",
            ondelete="CASCADE",
        ),
        Index("ix_case_signals_case", "case_id"),
        Index("ix_case_signals_signal", "signal_id"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    signal_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CaseNote(Base):
    __tablename__ = "case_notes"
    __table_args__ = (
        CheckConstraint("length(content) BETWEEN 1 AND 4000", name="ck_case_notes_content_length"),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_notes_case_organization",
            ondelete="CASCADE",
        ),
        Index("ix_case_notes_case_created", "case_id", "created_at"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    created_by_user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)


class CaseFinding(Base):
    __tablename__ = "case_findings"
    __table_args__ = (
        UniqueConstraint("case_id", "finding_id", name="uq_case_findings_case_finding"),
        UniqueConstraint("finding_id", "organization_id", name="uq_case_findings_finding_organization"),
        ForeignKeyConstraint(
            ["case_id", "organization_id"],
            ["incident_cases.id", "incident_cases.organization_id"],
            name="fk_case_findings_case_organization",
            ondelete="CASCADE",
        ),
        ForeignKeyConstraint(
            ["finding_id", "organization_id"],
            ["findings.id", "findings.organization_id"],
            name="fk_case_findings_finding_organization",
            ondelete="CASCADE",
        ),
        Index("ix_case_findings_case", "case_id"),
    )

    id: Mapped[str] = mapped_column(Uuid(as_uuid=False), primary_key=True, default=lambda: str(uuid4()))
    organization_id: Mapped[str] = mapped_column(ForeignKey("organizations.id", ondelete="CASCADE"), nullable=False)
    case_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
    finding_id: Mapped[str] = mapped_column(Uuid(as_uuid=False), nullable=False)
