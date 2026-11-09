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
