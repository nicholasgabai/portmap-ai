import json
import re
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
PORTAL_DIR = REPO_ROOT / "docs" / "portal"
MANIFEST_PATH = PORTAL_DIR / "manifest.json"

REQUIRED_SECTIONS = {
    "operator_guide",
    "developer_guide",
    "architecture_guide",
    "installation_guide",
    "raspberry_pi_guide",
    "packet_intelligence_guide",
    "ai_intelligence_guide",
    "deployment_guide",
    "governance_guide",
    "exports_guide",
    "troubleshooting_guide",
    "release_candidate_checklist",
    "open_source_enterprise_model",
}

FORBIDDEN_PLACEHOLDERS = ("TODO", "TBD", "FIXME")
FORBIDDEN_PATH_PATTERNS = ("/Users/", "/home/ng99", "/home/nico", "\\Users\\")
FORBIDDEN_SECRET_PATTERNS = (
    re.compile(r"sk-[A-Za-z0-9]{12,}"),
    re.compile(r"AKIA[0-9A-Z]{12,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)(api[_-]?key|secret|token)\s*[:=]\s*['\"][^'\"]+['\"]"),
)


def _manifest():
    with MANIFEST_PATH.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _portal_markdown_files():
    return sorted(PORTAL_DIR.glob("*.md"))


def test_manifest_exists_and_parses():
    assert MANIFEST_PATH.exists()
    manifest = _manifest()

    assert manifest["portal_version"] == "1.0"
    assert manifest["generated_at"] == "2026-07-01T00:00:00Z"
    assert isinstance(manifest["sections"], list)
    json.dumps(manifest, sort_keys=True)


def test_manifest_paths_exist_and_do_not_include_private_validation_doc():
    manifest = _manifest()

    for section in manifest["sections"]:
        path = section["path"]
        assert path.startswith("docs/portal/")
        assert path != "docs/real_device_validation.md"
        assert (REPO_ROOT / path).exists()


def test_section_ids_are_unique_and_required_sections_exist():
    sections = _manifest()["sections"]
    section_ids = [section["section_id"] for section in sections]

    assert len(section_ids) == len(set(section_ids))
    assert set(section_ids) == REQUIRED_SECTIONS


def test_manifest_ordering_is_deterministic():
    sections = _manifest()["sections"]
    orders = [section["order"] for section in sections]
    section_ids = [section["section_id"] for section in sections]

    assert orders == sorted(orders)
    assert orders == list(range(1, len(sections) + 1))
    assert section_ids == [section["section_id"] for section in sorted(sections, key=lambda row: row["order"])]


def test_required_markdown_files_have_titles():
    expected_files = {REPO_ROOT / section["path"] for section in _manifest()["sections"]}
    expected_files.add(PORTAL_DIR / "README.md")

    for path in sorted(expected_files):
        text = path.read_text(encoding="utf-8")
        first_line = text.splitlines()[0]
        assert first_line.startswith("# ")
        assert len(first_line.strip()) > 2


def test_no_placeholder_text_in_portal_docs():
    for path in _portal_markdown_files():
        text = path.read_text(encoding="utf-8")
        for placeholder in FORBIDDEN_PLACEHOLDERS:
            assert placeholder not in text


def test_no_sensitive_paths_or_sample_secrets_in_portal_docs():
    manifest_text = MANIFEST_PATH.read_text(encoding="utf-8")
    portal_text = "\n".join(path.read_text(encoding="utf-8") for path in _portal_markdown_files())
    combined = f"{manifest_text}\n{portal_text}"

    for pattern in FORBIDDEN_PATH_PATTERNS:
        assert pattern not in combined
    for pattern in FORBIDDEN_SECRET_PATTERNS:
        assert not pattern.search(combined)


def test_manifest_schema_fields_are_present_and_json_safe():
    for section in _manifest()["sections"]:
        assert set(section) == {
            "section_id",
            "title",
            "description",
            "path",
            "audience",
            "status",
            "order",
        }
        assert section["status"] == "active"
        assert section["audience"] in {"operators", "developers", "enterprise_evaluators"}
        json.dumps(section, sort_keys=True)
