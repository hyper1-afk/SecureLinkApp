from pathlib import Path

import yaml

ROOT = Path(__file__).parents[1]


def test_migration_image_contains_alembic_configuration_and_revisions() -> None:
    dockerfile = (ROOT / "apps" / "api" / "Dockerfile").read_text(encoding="utf-8")

    assert "COPY alembic.ini ./" in dockerfile
    assert "COPY migrations ./migrations" in dockerfile
    assert "HEALTHCHECK" not in dockerfile


def test_local_services_wait_for_the_one_shot_migration_job() -> None:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    services = compose["services"]

    migration = services["migrate"]
    assert migration["command"] == ["alembic", "upgrade", "head"]
    assert migration["environment"]["DATABASE_URL"] == "${DATABASE_URL:?Set DATABASE_URL in v2/.env}"
    assert migration["restart"] == "no"
    assert "env_file" not in migration

    for service_name in (
        "api", "email-worker", "domain-monitor-worker", "threat-feed-worker",
    ):
        assert services[service_name]["depends_on"]["migrate"]["condition"] == (
            "service_completed_successfully"
        )
    assert "healthcheck" in services["api"]
    assert all("healthcheck" not in services[name] for name in (
        "email-worker", "domain-monitor-worker", "threat-feed-worker",
    ))

