import tomllib
from pathlib import Path


def _load_pyproject():
    with open(Path("pyproject.toml"), "rb") as handle:
        return tomllib.load(handle)


def test_pyproject_declares_console_scripts():
    data = _load_pyproject()
    scripts = data["project"]["scripts"]

    assert scripts["portmap"] == "cli.main:main"
    assert scripts["portmap-orchestrator"] == "core_engine.orchestrator:main"
    assert scripts["portmap-master"] == "core_engine.master_node:main"
    assert scripts["portmap-worker"] == "core_engine.worker_node:main"
    assert scripts["portmap-dashboard"] == "cli.dashboard:main"


def test_pyproject_uses_runtime_requirements_file():
    data = _load_pyproject()

    assert data["project"]["dynamic"] == ["dependencies"]
    assert data["tool"]["setuptools"]["dynamic"]["dependencies"]["file"] == ["requirements.txt"]


def test_pyproject_includes_local_config_and_docs_data_files():
    data = _load_pyproject()
    data_files = data["tool"]["setuptools"]["data-files"]
    package_data = data["tool"]["setuptools"]["package-data"]

    assert package_data["core_engine"] == ["default_configs/*.json"]
    assert "share/portmap-ai/config/profiles" in data_files
    assert "config/profiles/default.json" in data_files["share/portmap-ai/config/profiles"]
    assert "config/profiles/raspberry_pi.json" in data_files["share/portmap-ai/config/profiles"]
    assert "share/portmap-ai/systemd" in data_files
    assert "deploy/systemd/portmap-ai-stack.service" in data_files["share/portmap-ai/systemd"]
    assert "deploy/systemd/portmap-ai-worker.service" in data_files["share/portmap-ai/systemd"]
    assert "share/portmap-ai/scripts" in data_files
    assert "scripts/install_systemd_user.sh" in data_files["share/portmap-ai/scripts"]
    assert "share/portmap-ai" in data_files
    assert "CHANGELOG.md" in data_files["share/portmap-ai"]
    assert "SECURITY.md" in data_files["share/portmap-ai"]
    assert "docs/quick_start.md" in data_files["share/portmap-ai/docs"]
    assert "docs/architecture.md" in data_files["share/portmap-ai/docs"]
    assert "docs/ai_layer.md" in data_files["share/portmap-ai/docs"]
    assert "docs/deployment_options.md" in data_files["share/portmap-ai/docs"]
    assert "docs/docker_deployment.md" in data_files["share/portmap-ai/docs"]
    assert "docs/logging_audit.md" in data_files["share/portmap-ai/docs"]
    assert "docs/network_control_layer.md" in data_files["share/portmap-ai/docs"]
    assert "docs/packaging.md" in data_files["share/portmap-ai/docs"]
    assert "docs/platform_abstraction.md" in data_files["share/portmap-ai/docs"]
    assert "docs/raspberry_pi_deployment.md" in data_files["share/portmap-ai/docs"]
    assert "docs/release_candidate.md" in data_files["share/portmap-ai/docs"]
    assert "docs/remediation_safety.md" in data_files["share/portmap-ai/docs"]
    assert "docs/saas_architecture.md" in data_files["share/portmap-ai/docs"]
    assert "docs/scanner_risk_engine.md" in data_files["share/portmap-ai/docs"]
    assert "docs/security_authentication.md" in data_files["share/portmap-ai/docs"]
    assert "docs/stack_stability.md" in data_files["share/portmap-ai/docs"]
    assert "docs/tui_dashboard.md" in data_files["share/portmap-ai/docs"]
    assert "tests/node_configs/orchestrator.json" in data_files["share/portmap-ai/node_configs"]


def test_packaged_stack_defaults_exist():
    from core_engine import stack_launcher

    assert stack_launcher.DEFAULT_ORCHESTRATOR_CFG.endswith("orchestrator.json")
    assert Path(stack_launcher.DEFAULT_ORCHESTRATOR_CFG).exists()
    assert Path(stack_launcher.DEFAULT_MASTER_CFG).exists()
    assert Path(stack_launcher.DEFAULT_WORKER_CFG).exists()


def test_local_package_script_points_users_to_runtime_setup():
    text = Path("scripts/package_local.sh").read_text()

    assert "pip install -r requirements.txt" in text
    assert "portmap setup" in text
    assert "portmap doctor" in text
    assert "Docker is optional" in text
