import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError


@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL CI service is not configured")
def test_postgres_migration_installs_append_only_audit_trigger():
    engine = create_engine(os.environ["DATABASE_URL"])
    organization_id = str(uuid4())
    event_id = str(uuid4())
    try:
        with engine.connect() as connection:
            transaction = connection.begin()
            connection.execute(
                text(
                    "INSERT INTO organizations (id, name, created_at) "
                    "VALUES (:id, :name, now())"
                ),
                {"id": organization_id, "name": "Migration test"},
            )
            connection.execute(
                text(
                    "INSERT INTO audit_events "
                    "(id, organization_id, actor_type, action, target_type, details) "
                    "VALUES (:id, :org_id, 'system', 'test.created', 'test', '{}')"
                ),
                {"id": event_id, "org_id": organization_id},
            )
            with pytest.raises(DBAPIError):
                connection.execute(
                    text("UPDATE audit_events SET action = 'tampered' WHERE id = :id"),
                    {"id": event_id},
                )
            transaction.rollback()
    finally:
        engine.dispose()


@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL CI service is not configured")
def test_postgres_scan_evidence_rejects_update_and_delete():
    engine = create_engine(os.environ["DATABASE_URL"])
    organization_id = str(uuid4())
    scan_id = str(uuid4())
    evidence_id = str(uuid4())
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO organizations (id, name, created_at) "
                    "VALUES (:id, 'Scan evidence test', now())"
                ),
                {"id": organization_id},
            )
            connection.execute(
                text(
                    "INSERT INTO url_scans "
                    "(id, organization_id, requested_by_user_id, display_url, hostname, scheme, status, created_at) "
                    "VALUES (:id, :org_id, NULL, 'https://example.test/[redacted]', "
                    "'example.test', 'https', 'completed', now())"
                ),
                {"id": scan_id, "org_id": organization_id},
            )
            connection.execute(
                text(
                    "INSERT INTO scan_evidence "
                    "(id, organization_id, scan_id, source_type, detector_version, content_hash, payload, created_at) "
                    "VALUES (:id, :org_id, :scan_id, 'passive_url_parser', 'url-hygiene-v1', "
                    "'0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef', '{}', now())"
                ),
                {"id": evidence_id, "org_id": organization_id, "scan_id": scan_id},
            )
        for statement in (
            "UPDATE scan_evidence SET payload = '{}' WHERE id = :id",
            "DELETE FROM scan_evidence WHERE id = :id",
        ):
            with engine.connect() as connection:
                transaction = connection.begin()
                with pytest.raises(DBAPIError):
                    connection.execute(text(statement), {"id": evidence_id})
                transaction.rollback()
    finally:
        engine.dispose()




@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL CI service is not configured")
def test_postgres_security_signals_reject_update_and_delete():
    engine = create_engine(os.environ["DATABASE_URL"])
    organization_id = str(uuid4())
    signal_id = str(uuid4())
    case_id = str(uuid4())
    case_signal_id = str(uuid4())
    note_id = str(uuid4())
    try:
        with engine.begin() as connection:
            connection.execute(
                text(
                    "INSERT INTO organizations (id, name, created_at) "
                    "VALUES (:id, 'Signal immutability test', now())"
                ),
                {"id": organization_id},
            )
            connection.execute(
                text(
                    "INSERT INTO security_signals "
                    "(id, organization_id, source_type, source_reference, signal_type, subject, "
                    "severity, title, summary, observed_at, payload, content_hash) "
                    "VALUES (:id, :org_id, 'integration', 'test-source-1', 'test_signal', "
                    "'example.test', 'medium', 'Test signal', 'Immutable evidence fixture', "
                    "now(), '{}', '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef')"
                ),
                {"id": signal_id, "org_id": organization_id},
            )
            connection.execute(
                text(
                    "INSERT INTO incident_cases "
                    "(id, organization_id, scan_id, status, severity, title, summary) "
                    "VALUES (:id, :org_id, NULL, 'open', 'medium', 'Test case', 'Test case summary')"
                ),
                {"id": case_id, "org_id": organization_id},
            )
            connection.execute(
                text(
                    "INSERT INTO case_signals (id, organization_id, case_id, signal_id) "
                    "VALUES (:id, :org_id, :case_id, :signal_id)"
                ),
                {
                    "id": case_signal_id,
                    "org_id": organization_id,
                    "case_id": case_id,
                    "signal_id": signal_id,
                },
            )
            connection.execute(
                text(
                    "INSERT INTO case_notes (id, organization_id, case_id, content) "
                    "VALUES (:id, :org_id, :case_id, 'Reviewed the evidence fixture')"
                ),
                {"id": note_id, "org_id": organization_id, "case_id": case_id},
            )
        statements = (
            "UPDATE security_signals SET summary = 'tampered' WHERE id = :id",
            "DELETE FROM security_signals WHERE id = :id",
        )
        for statement in statements:
            with engine.connect() as connection:
                transaction = connection.begin()
                with pytest.raises(DBAPIError):
                    connection.execute(text(statement), {"id": signal_id})
                transaction.rollback()
        for statement in (
            "UPDATE case_signals SET signal_id = :replacement WHERE id = :id",
            "DELETE FROM case_signals WHERE id = :id",
        ):
            with engine.connect() as connection:
                transaction = connection.begin()
                with pytest.raises(DBAPIError):
                    connection.execute(
                        text(statement), {"id": case_signal_id, "replacement": str(uuid4())}
                    )
                transaction.rollback()
        for statement in (
            "UPDATE case_notes SET content = 'tampered' WHERE id = :id",
            "DELETE FROM case_notes WHERE id = :id",
        ):
            with engine.connect() as connection:
                transaction = connection.begin()
                with pytest.raises(DBAPIError):
                    connection.execute(text(statement), {"id": note_id})
                transaction.rollback()
    finally:
        engine.dispose()


@pytest.mark.skipif(not os.getenv("DATABASE_URL"), reason="PostgreSQL CI service is not configured")
def test_postgres_case_approval_allows_one_decision_then_rejects_mutation():
    engine = create_engine(os.environ["DATABASE_URL"])
    organization_id, requester_id, reviewer_id, case_id, approval_id = (str(uuid4()) for _ in range(5))
    try:
        with engine.begin() as connection:
            connection.execute(
                text("INSERT INTO organizations (id, name, created_at) VALUES (:id, 'Approval test', now())"),
                {"id": organization_id},
            )
            for user_id, email in ((requester_id, "requester@test.invalid"), (reviewer_id, "reviewer@test.invalid")):
                connection.execute(
                    text(
                        "INSERT INTO users (id, email, email_normalized, password_hash, is_active, created_at) "
                        "VALUES (:id, :email, :email, 'test-hash', true, now())"
                    ),
                    {"id": user_id, "email": email},
                )
            connection.execute(
                text(
                    "INSERT INTO incident_cases (id, organization_id, scan_id, status, severity, title, summary) "
                    "VALUES (:id, :org_id, NULL, 'awaiting_approval', 'high', 'Test approval', 'Approval fixture')"
                ),
                {"id": case_id, "org_id": organization_id},
            )
            connection.execute(
                text(
                    "INSERT INTO case_approvals "
                    "(id, organization_id, case_id, action, rationale, status, requester_user_id, expires_at) "
                    "VALUES (:id, :org_id, :case_id, 'revoke_extension_sessions', 'Contain incident', "
                    "'pending', :requester_id, now() + interval '1 hour')"
                ),
                {"id": approval_id, "org_id": organization_id, "case_id": case_id, "requester_id": requester_id},
            )
            connection.execute(
                text(
                    "UPDATE case_approvals SET status = 'approved', reviewer_user_id = :reviewer_id, "
                    "decided_at = now() WHERE id = :id"
                ),
                {"reviewer_id": reviewer_id, "id": approval_id},
            )
        for statement in (
            "UPDATE case_approvals SET rationale = 'tampered' WHERE id = :id",
            "DELETE FROM case_approvals WHERE id = :id",
        ):
            with engine.connect() as connection:
                transaction = connection.begin()
                with pytest.raises(DBAPIError):
                    connection.execute(text(statement), {"id": approval_id})
                transaction.rollback()
    finally:
        engine.dispose()
