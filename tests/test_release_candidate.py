import tomllib
from pathlib import Path


def test_project_version_matches_release_candidate_docs():
    with Path("pyproject.toml").open("rb") as handle:
        pyproject = tomllib.load(handle)

    changelog = Path("CHANGELOG.md").read_text()
    release_doc = Path("docs/release_candidate.md").read_text()

    assert pyproject["project"]["version"] == "0.1.0"
    assert "## 0.1.0 - Release Candidate" in changelog
    assert "PortMap-AI 0.1.0 Release Candidate" in release_doc


def test_release_candidate_docs_include_required_operator_checks():
    release_doc = Path("docs/release_candidate.md").read_text()

    assert "python -m pytest" in release_doc
    assert "portmap setup --output json" in release_doc
    assert "portmap doctor --output json" in release_doc
    assert "python -m pip wheel" in release_doc
    assert "Docker is not required" in release_doc


def test_documentation_index_points_to_phase_16_18_guides():
    index = Path("docs/README.txt").read_text()

    assert "docs/architecture.md" in index
    assert "docs/saas_architecture.md" in index
    assert "docs/release_candidate.md" in index
    assert "CHANGELOG.md" in index
