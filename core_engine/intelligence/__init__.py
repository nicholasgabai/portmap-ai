from __future__ import annotations

from core_engine.intelligence.dns_analytics import (
    DNSAnalyticsRecord,
    build_dns_analytics,
    build_resolver_behavior_summary,
    empty_dns_analytics,
    summarize_domain_patterns,
    summarize_ioc_matches,
)
from core_engine.intelligence.domain_patterns import (
    DomainPatternRecord,
    analyze_domain_pattern,
    analyze_domain_patterns,
    build_domain_pattern_record,
    dns_tunneling_candidate,
    hash_domain,
    label_entropy,
    normalize_domain,
    redacted_domain_preview,
    repeated_subdomain_detected,
)
from core_engine.intelligence.ioc_exports import (
    IOCExportSummary,
    build_ioc_export_summary,
    ioc_summary_to_csv_rows,
)
from core_engine.intelligence.ioc_inventory import (
    IOCInventorySummary,
    build_ioc_inventory,
    empty_ioc_inventory,
)
from core_engine.intelligence.ioc_matching import (
    IOCMatchRecord,
    match_ioc,
    match_iocs,
)
from core_engine.intelligence.ioc_records import (
    IOCRecord,
    IOCRecordError,
    build_ioc_record,
    deterministic_ioc_json,
    normalize_ioc_source_category,
    normalize_ioc_type,
    normalize_ioc_value,
)
from core_engine.intelligence.signature_matching import (
    SignatureMatchRecord,
    match_signature,
    match_signatures,
)
from core_engine.intelligence.signature_records import (
    SignatureRecord,
    SignatureRecordError,
    build_signature_record,
    empty_signature_record,
    validate_match_conditions,
)

__all__ = [
    "DNSAnalyticsRecord",
    "DomainPatternRecord",
    "IOCExportSummary",
    "IOCInventorySummary",
    "IOCMatchRecord",
    "IOCRecord",
    "IOCRecordError",
    "SignatureMatchRecord",
    "SignatureRecord",
    "SignatureRecordError",
    "analyze_domain_pattern",
    "analyze_domain_patterns",
    "build_dns_analytics",
    "build_domain_pattern_record",
    "build_ioc_export_summary",
    "build_ioc_inventory",
    "build_ioc_record",
    "build_resolver_behavior_summary",
    "build_signature_record",
    "deterministic_ioc_json",
    "dns_tunneling_candidate",
    "empty_dns_analytics",
    "empty_ioc_inventory",
    "empty_signature_record",
    "hash_domain",
    "ioc_summary_to_csv_rows",
    "label_entropy",
    "match_ioc",
    "match_iocs",
    "match_signature",
    "match_signatures",
    "normalize_domain",
    "normalize_ioc_source_category",
    "normalize_ioc_type",
    "normalize_ioc_value",
    "redacted_domain_preview",
    "repeated_subdomain_detected",
    "summarize_domain_patterns",
    "summarize_ioc_matches",
    "validate_match_conditions",
]
