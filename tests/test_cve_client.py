import json

from core_engine.vuln.cve_client import analyze_service_cves, fetch_nvd_cves, load_cves_from_json, normalize_cve_record
from core_engine.vuln.cve_store import load_cve_cache, merge_cve_records, save_cve_cache
from core_engine.vuln.cvss import advisory_risk_score, severity_from_score


def _timestamp(date, *parts):
    return f"{date}T{':'.join(parts)}.000"


NVD_RECORD = {
    "cve": {
        "id": "CVE-2021-41773",
        "sourceIdentifier": "security@example.test",
        "published": _timestamp("2021-10-05", "12", "00", "00"),
        "lastModified": _timestamp("2021-10-06", "12", "00", "00"),
        "descriptions": [
            {"lang": "en", "value": "Apache HTTP Server 2.4.49 path traversal vulnerability."}
        ],
        "metrics": {
            "cvssMetricV31": [
                {
                    "type": "Primary",
                    "cvssData": {
                        "version": "3.1",
                        "baseScore": 7.5,
                        "baseSeverity": "HIGH",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                    },
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-22"}]}],
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {"criteria": "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
                        ]
                    }
                ]
            }
        ],
        "references": {"referenceData": [{"url": "https://example.test/CVE-2021-41773"}]},
    }
}


def test_cvss_severity_and_advisory_risk_helpers():
    assert severity_from_score(9.8) == "critical"
    assert severity_from_score(7.5) == "high"
    assert advisory_risk_score(7.5, exposed=True, version_match=True) == 0.88


def test_normalize_nvd_cve_record_extracts_fields():
    row = normalize_cve_record(NVD_RECORD)

    assert row["id"] == "CVE-2021-41773"
    assert row["severity"] == "high"
    assert row["cvss_score"] == 7.5
    assert row["cvss"]["vector"].startswith("CVSS:3.1/")
    assert row["cwes"] == ["CWE-22"]
    assert row["cpes"] == ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"]
    assert row["raw_payload_stored"] is False


def test_service_cve_matching_scores_version_and_service():
    cves = [normalize_cve_record(NVD_RECORD)]
    services = [{"target": "127.0.0.1", "port": 80, "state": "open", "service": "HTTP", "version": "Apache/2.4.49"}]

    report = analyze_service_cves(services, cves)

    assert report["ok"] is True
    assert report["automatic_changes"] is False
    assert report["match_count"] == 1
    match = report["matches"][0]
    assert match["cve_id"] == "CVE-2021-41773"
    assert match["confidence"] >= 0.9
    assert match["risk_score"] >= 0.8
    assert "version" in match["match_reasons"]


def test_cve_cache_merges_and_persists_records(tmp_path):
    cache_path = tmp_path / "cve_cache.json"
    existing = [{"id": "CVE-2021-0001", "summary": "old"}]
    incoming = [{"id": "cve-2021-0001", "severity": "high"}, {"id": "CVE-2021-0002"}]

    merged = merge_cve_records(existing, incoming)
    saved = save_cve_cache(merged, path=cache_path, metadata={"source": "test"})
    loaded = load_cve_cache(cache_path)

    assert saved["record_count"] == 2
    assert loaded["record_count"] == 2
    assert loaded["metadata"] == {"source": "test"}
    assert loaded["records"][0]["id"] == "CVE-2021-0001"
    assert loaded["records"][0]["severity"] == "high"


def test_load_cves_from_json_accepts_nvd_payload():
    payload = json.dumps({"vulnerabilities": [NVD_RECORD]})

    rows = load_cves_from_json(payload)

    assert [row["id"] for row in rows] == ["CVE-2021-41773"]


def test_fetch_nvd_cves_uses_keyword_query_and_normalizes_response():
    seen = {}

    class FakeResponse:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self):
            return json.dumps({"totalResults": 1, "vulnerabilities": [NVD_RECORD]}).encode("utf-8")

    def opener(req, timeout=10.0):
        seen["url"] = req.full_url
        seen["timeout"] = timeout
        return FakeResponse()

    report = fetch_nvd_cves(keyword="apache http server", limit=1, opener=opener, timeout=2.0)

    assert "keywordSearch=apache+http+server" in seen["url"]
    assert seen["timeout"] == 2.0
    assert report["record_count"] == 1
    assert report["records"][0]["id"] == "CVE-2021-41773"
