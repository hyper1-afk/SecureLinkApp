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
