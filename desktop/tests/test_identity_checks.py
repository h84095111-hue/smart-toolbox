import json
from pathlib import Path

import pytest

from smartintel.identity_checks import (
    _valid_username, check_username, extract_profile_metadata,
    inspect_email_domain, inspect_phone_number, parse_maigret_report,
)


def test_username_validation():
    assert _valid_username("@alice.test") == "alice.test"
    with pytest.raises(ValueError):
        _valid_username("alice;rm -rf")


def test_parse_maigret_simple_json(tmp_path):
    report = tmp_path / "result.json"
    report.write_text(json.dumps({
        "GitHub": {"status": "Claimed", "url_user": "https://github.com/alice"},
        "Reddit": {"status": "Available", "url_user": "https://reddit.com/user/alice"},
    }), encoding="utf-8")
    rows = parse_maigret_report(report, "alice")
    assert len(rows) == 1
    assert rows[0].url == "https://github.com/alice"
    assert rows[0].status == "possible_profile"


def test_parse_maigret_ndjson(tmp_path):
    report = tmp_path / "result.json"
    report.write_text(
        '{"sitename":"GitHub","status":"Claimed","url_user":"https://github.com/a"}\n'
        '{"sitename":"X","status":"Available","url_user":"https://x.com/a"}',
        encoding="utf-8",
    )
    assert len(parse_maigret_report(report, "a")) == 1


def test_username_site_limit_is_bounded():
    with pytest.raises(ValueError):
        check_username("alice", max_sites=5000)


def test_email_domain_check_does_not_claim_mailbox_exists():
    result = inspect_email_domain("person@example.com")
    assert result["identifier_type"] == "email"
    assert "cannot confirm" in result["limitations"]


def test_phone_rejects_url_or_injection():
    with pytest.raises(ValueError):
        inspect_phone_number("https://example.com")


def test_profile_metadata_extracts_public_fields():
    html = """<html><head><title>Alice</title>
    <meta property="og:title" content="Alice Example">
    <meta property="og:description" content="Public bio">
    <link rel="canonical" href="https://example.com/@alice">
    </head><body><a rel="me" href="https://github.com/alice">GitHub</a></body></html>"""
    result = extract_profile_metadata(html, "https://example.com/@alice")
    assert result["display_name"] == "Alice Example"
    assert result["rel_me_links"] == ["https://github.com/alice"]
