import json
import re

from core_engine.streams import detect_patterns, normalize_patterns, parse_stream_bytes, parse_stream_file


PRIVATE_PATTERNS = [
    re.compile(r"192\.168\."),
    re.compile(r"10\.[0-9]+\."),
    re.compile(r"172\.(1[6-9]|2[0-9]|3[0-1])\."),
    re.compile(r"/home/"),
    re.compile(r"/Users/"),
    re.compile(r"([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}"),
]


def _patterns():
    return [
        {"name": "sample-text-marker", "type": "string", "value": "HELLO"},
        {"name": "sample-hex-marker", "type": "hex", "value": "414243"},
    ]


def test_parse_empty_stream_returns_empty_metadata():
    result = parse_stream_bytes(b"", patterns=_patterns())

    assert result["ok"] is True
    assert result["frame_count"] == 0
    assert result["length_summary"]["max"] == 0
    assert result["raw_payload_stored"] is False
    assert result["metadata_only"] is True


def test_parse_single_frame_metadata_and_markers():
    result = parse_stream_bytes(b"HELLO ABC sample", patterns=_patterns())

    assert result["ok"] is True
    assert result["frame_count"] == 1
    assert result["frames"][0]["length"] == 16
    assert result["frames"][0]["printable_ratio"] == 1.0
    assert result["frames"][0]["hex_summary"] == b"HELLO ABC sample"[:16].hex()
    assert result["detected_markers"] == ["sample-hex-marker", "sample-text-marker"]
    json.dumps(result)


def test_parse_fixed_size_frames_and_frame_limit():
    result = parse_stream_bytes(b"aaaabbbbccccdddd", frame_size=4, max_frames=3)

    assert result["ok"] is False
    assert result["status"] == "input_limited"
    assert result["frame_count"] == 3
    assert result["length_summary"]["average"] == 4


def test_parse_delimited_frames():
    result = parse_stream_bytes(b"one|two|three", delimiter=b"|")

    assert result["ok"] is True
    assert result["frame_count"] == 3
    assert [frame["length"] for frame in result["frames"]] == [3, 3, 5]


def test_parse_length_prefixed_frames_and_malformed_tail():
    valid = parse_stream_bytes(b"\x03ABC\x02DE", length_prefix_bytes=1)
    malformed = parse_stream_bytes(b"\x04ABC", length_prefix_bytes=1)

    assert valid["ok"] is True
    assert valid["frame_count"] == 2
    assert malformed["ok"] is False
    assert malformed["status"] == "malformed"
    assert "declared frame length" in malformed["errors"][0]


def test_oversized_input_is_limited_without_frames():
    result = parse_stream_bytes(b"sample-data", max_input_bytes=4)

    assert result["ok"] is False
    assert result["status"] == "input_limited"
    assert result["frame_count"] == 0


def test_pattern_normalization_and_detection():
    normalized = normalize_patterns(_patterns())
    markers = detect_patterns(b"hello ABC HELLO", _patterns())

    assert normalized["ok"] is True
    assert len(normalized["patterns"]) == 2
    assert {marker["name"] for marker in markers} == {"sample-text-marker", "sample-hex-marker"}
    assert all("_bytes" not in pattern for pattern in normalized["patterns"])


def test_invalid_pattern_returns_unsupported_parse_result():
    result = parse_stream_bytes(b"sample", patterns=[{"name": "bad", "type": "hex", "value": "not-hex"}])

    assert result["ok"] is False
    assert result["status"] == "unsupported"
    assert result["frames"] == []


def test_parse_local_file_uses_summary_without_path(tmp_path):
    sample = tmp_path / "sample_stream.bin"
    sample.write_bytes(b"HELLO|ABC")

    result = parse_stream_file(sample, delimiter=b"|", patterns=_patterns())

    assert result["ok"] is True
    assert result["source"] == "local_file"
    assert result["file_summary"]["name"] == "sample_stream.bin"
    assert result["file_summary"]["path_stored"] is False
    assert str(tmp_path) not in repr(result)


def test_no_private_identifiers_in_examples_or_output(tmp_path):
    sample = tmp_path / "sample_stream.bin"
    sample.write_bytes(b"HELLO ABC sample")
    output = repr(parse_stream_file(sample, patterns=_patterns()))

    for pattern in PRIVATE_PATTERNS:
        assert not pattern.search(output)
