from pathlib import Path

import yaml

SPEC_PATH = (
    Path(__file__).parents[1]
    / "deploy"
    / "digitalocean"
    / "app-spec.staging.yaml"
)


def test_digitalocean_spec_is_manual_and_uses_the_v2_branch_only() -> None:
    spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))

    assert spec["name"] == "securelink-v2-staging"
    assert spec["region"] == "atl"
    assert {component["name"] for component in spec["services"]} == {"api"}
    assert {component["name"] for component in spec["workers"]} == {"email-worker"}
    for component in [*spec["services"], *spec["workers"], *spec["jobs"]]:
        assert component["github"]["branch"] == "securelink-v2"
        assert component["github"]["deploy_on_push"] is False
        assert component["source_dir"] == "v2"
        assert component["dockerfile_path"] == "v2/apps/api/Dockerfile"


def test_migrations_run_once_before_manual_staging_deployments() -> None:
    spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    assert len(spec["jobs"]) == 1
    migration = spec["jobs"][0]
    assert migration["name"] == "database-migrations"
    assert migration["kind"] == "PRE_DEPLOY"
    assert migration["run_command"] == "alembic upgrade head"


def test_api_health_and_app_alerts_are_configured() -> None:
    spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    api = spec["services"][0]
    assert api["http_port"] == 8000
    assert api["health_check"]["http_path"] == "/health/ready"
    assert api["liveness_health_check"]["http_path"] == "/health/live"
    assert any(alert["rule"] == "DEPLOYMENT_FAILED" for alert in spec["alerts"])


def test_runtime_settings_are_defined_on_app_and_worker_components() -> None:
    spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    expected_envs = {
        "APP_ENV": "staging",
        "APP_PUBLIC_URL": "${APP_URL}",
        "SMTP_STARTTLS": "true",
    }

    assert "envs" not in spec
    for component in [spec["services"][0], spec["workers"][0]]:
        envs = {env["key"]: env for env in component["envs"]}
        assert {key: env["value"] for key, env in envs.items()} == expected_envs
        assert all(env["scope"] == "RUN_TIME" for env in envs.values())
        assert all(env["type"] == "GENERAL" for env in envs.values())


def test_spec_contains_no_secrets_or_domain_monitor_worker() -> None:
    spec = yaml.safe_load(SPEC_PATH.read_text(encoding="utf-8"))
    serialized = SPEC_PATH.read_text(encoding="utf-8").casefold()

    assert "domain-monitor-worker" not in {worker["name"] for worker in spec["workers"]}
    assert all(env.get("type") != "SECRET" for env in spec["envs"])
    assert "database_url" not in {env["key"].casefold() for env in spec["envs"]}
    assert "rediss://" not in serialized
    assert "postgresql+psycopg://" not in serialized
