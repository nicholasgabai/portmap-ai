from pathlib import Path

from core_engine.config_validation import validate_config_file


def test_docker_compose_declares_core_services_and_persistent_volume():
    compose = Path("docker-compose.yml").read_text()

    assert "orchestrator:" in compose
    assert "master:" in compose
    assert "worker:" in compose
    assert "portmap-runtime:/root/.portmap-ai" in compose
    assert "docker/config/orchestrator.json" in compose
    assert "docker/config/master.json" in compose
    assert "docker/config/worker.json" in compose
    assert "/healthz" in compose
    assert "/metrics" not in compose  # metrics stays runtime/API, not healthcheck coupling
    assert "PORTMAP_ORCHESTRATOR_TOKEN:?" in compose
    assert ":-test-token" not in compose


def test_docker_configs_validate_with_explicit_token_environment(monkeypatch):
    monkeypatch.setenv("PORTMAP_ORCHESTRATOR_TOKEN", "docker-token-value-123456")
    configs = [
        ("docker/config/orchestrator.json", "orchestrator"),
        ("docker/config/master.json", "master"),
        ("docker/config/worker.json", "worker"),
    ]

    for path, role in configs:
        result = validate_config_file(path, include_settings=False, expected_role=role)
        assert result.ok, result.to_dict()


def test_dockerfiles_install_runtime_package_not_dev_requirements():
    for path in [
        Path("docker/orchestrator.Dockerfile"),
        Path("docker/master.Dockerfile"),
        Path("docker/worker.Dockerfile"),
    ]:
        text = path.read_text()
        assert "pip install --no-cache-dir ." in text
        assert "requirements-dev.txt" not in text


def test_dockerignore_excludes_local_runtime_artifacts():
    text = Path(".dockerignore").read_text()

    assert "portmap-ai-env" in text
    assert "logs/" in text
    assert "data/" in text
    assert "*.jsonl" in text
