import json
from pathlib import Path

import pytest

from smartintel.identity_checks import (
    _valid_username, check_username, extract_profile_metadata,
    inspect_email_domain, inspect_phone_number, parse_maigret_report,
    PivotQueue, check_identity,
)


def test_username_validation():
    assert _valid_username("@alice.test") == "alice.test"
    with pytest.raises(ValueError):
        _valid_username("--help")
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



def test_pivot_queue_requires_explicit_approval_and_evidence():
    queue = PivotQueue(max_depth=2, max_targets=3)
    item = queue.propose("alice2", source_url="https://example.org/profile/alice",
                         reason="Public profile links to this handle", depth=1)
    assert item["status"] == "pending_analyst_approval"
    assert queue.list()[0]["status"] == "pending_analyst_approval"
    assert queue.approve("alice2")["status"] == "approved"


def test_pivot_queue_enforces_depth_and_evidence():
    queue = PivotQueue(max_depth=1)
    with pytest.raises(ValueError):
        queue.propose("alice2", source_url="https://example.org/a", reason="test", depth=2)
    with pytest.raises(ValueError):
        queue.propose("alice3", source_url="file:///tmp/a", reason="test", depth=1)


def test_identity_dispatcher_rejects_unknown_type():
    with pytest.raises(ValueError):
        check_identity("password", "anything")



def test_profile_url_rejects_local_hosts():
    from smartintel.identity_checks import _public_profile_url
    with pytest.raises(ValueError):
        _public_profile_url("http://127.0.0.1/admin")
    with pytest.raises(ValueError):
        _public_profile_url("file:///etc/passwd")


def test_profile_parser_extracts_only_explicit_rel_me_pivots(monkeypatch):
    import socket
    import requests
    from smartintel.identity_checks import fetch_public_profile_metadata

    monkeypatch.setattr(socket, "getaddrinfo", lambda *args, **kwargs: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 443))
    ])

    class FakeResponse:
        headers = {"Content-Type": "text/html; charset=utf-8"}
        encoding = "utf-8"
        is_redirect = False
        is_permanent_redirect = False
        def raise_for_status(self): pass
        def iter_content(self, chunk_size=65536):
            yield b'<html><head><title>Public page</title></head><body><a rel="me" href="https://social.example/@alice2">profile</a></body></html>'
        def close(self): pass

    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: FakeResponse())
    result = fetch_public_profile_metadata("https://example.org/@alice")
    assert result["profile"]["title"] == "Public page"
    assert result["pivot_candidates"][0]["username"] == "alice2"
    assert result["pivot_candidates"][0]["status"] == "pending_analyst_approval"
