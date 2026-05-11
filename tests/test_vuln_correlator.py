from core_engine.vuln.vuln_correlator import classify_exposure, correlate_vulnerabilities, exploitability_indicators


SERVICE = {
    "target": "203.0.113.10",
    "port": 80,
    "state": "open",
    "service": "HTTP",
    "version": "Apache/2.4.49",
    "classification": "public_interface",
}


CVE_MATCH = {
    "target": "203.0.113.10",
    "port": 80,
    "service": "HTTP",
    "version": "Apache/2.4.49",
    "cve_id": "CVE-2021-41773",
    "severity": "high",
    "cvss_score": 7.5,
    "risk_score": 0.88,
    "confidence": 0.95,
    "match_reasons": ["service_name", "version"],
    "known_exploited": True,
    "ransomware_association": True,
    "ransomware_families": ["examplelocker"],
    "summary": "Apache HTTP Server 2.4.49 path traversal and remote code execution used by ransomware actors.",
}


def test_correlate_vulnerabilities_prioritizes_known_exploited_public_risk():
    report = correlate_vulnerabilities(services=[SERVICE], cve_matches=[CVE_MATCH])

    assert report["ok"] is True
    assert report["automatic_changes"] is False
    assert report["raw_payload_stored"] is False
    assert report["vulnerability_count"] == 1
    finding = report["vulnerabilities"][0]
    assert finding["priority"] == "critical"
    assert finding["priority_score"] == 1.0
    assert finding["known_exploited"] is True
    assert finding["ransomware_association"] is True
    assert finding["ransomware_families"] == ["examplelocker"]
    assert finding["exposure"]["public"] is True
    assert "remote_code_execution" in finding["exploitability_indicators"]
    assert "prioritize_known_exploited_vulnerability_review" in finding["recommended_actions"]
    assert "priority is critical" in finding["explanation"]


def test_correlate_vulnerabilities_can_match_raw_cves_to_services():
    cve = {
        "id": "CVE-2024-0001",
        "summary": "OpenSSH 9.1 unauthenticated remote code execution vulnerability.",
        "severity": "critical",
        "cvss_score": 9.8,
        "cpes": ["cpe:2.3:a:openbsd:openssh:9.1:*:*:*:*:*:*:*"],
    }
    service = {
        "target": "203.0.113.5",
        "port": 22,
        "state": "open",
        "service": "SSH",
        "version": "OpenSSH_9.1",
    }

    report = correlate_vulnerabilities(services=[service], cves=[cve])

    assert report["cve_match_count"] == 1
    assert report["vulnerabilities"][0]["cve_id"] == "CVE-2024-0001"
    assert report["vulnerabilities"][0]["priority"] == "critical"
    assert "remote_code_execution" in report["vulnerabilities"][0]["exploitability_indicators"]


def test_exposure_classification_handles_all_interfaces_and_lan():
    all_interfaces = classify_exposure({"state": "listening", "bind_address": "0.0.0.0"})
    lan = classify_exposure({"state": "open", "classification": "lan_interface"})

    assert all_interfaces["scope"] == "all_interfaces"
    assert all_interfaces["all_interfaces"] is True
    assert lan["scope"] == "lan"
    assert lan["lan"] is True


def test_exploitability_indicators_detect_common_terms():
    indicators = exploitability_indicators({
        "summary": "SQL injection allows authentication bypass and credential disclosure.",
        "known_exploited": True,
    })

    assert indicators == ["authentication_bypass", "credential_exposure", "known_exploited", "sql_injection"]


def test_correlator_dedupes_and_sorts_findings():
    low = {
        **CVE_MATCH,
        "cve_id": "CVE-2024-LOW",
        "severity": "low",
        "cvss_score": 2.0,
        "risk_score": 0.2,
        "known_exploited": False,
        "ransomware_association": False,
        "summary": "low severity information disclosure",
    }

    report = correlate_vulnerabilities(services=[SERVICE], cve_matches=[low, CVE_MATCH, CVE_MATCH])

    assert report["cve_match_count"] == 3
    assert report["vulnerability_count"] == 2
    assert report["vulnerabilities"][0]["cve_id"] == "CVE-2021-41773"


def test_correlator_accepts_empty_inputs():
    report = correlate_vulnerabilities()

    assert report["ok"] is True
    assert report["vulnerability_count"] == 0
    assert report["vulnerabilities"] == []
