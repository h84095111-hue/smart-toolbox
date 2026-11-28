from smartintel.collectors.all_in_one import _target_kind, build_registry
from smartintel.source_catalog import SOURCE_CATALOG


def test_all_in_one_registry_uses_implemented_catalogue_adapters():
    registry = build_registry()
    names = {item.name for item in registry.list()}
    assert {"crtsh", "wayback", "virustotal", "urlscan", "otx", "securitytrails", "gdelt"} <= names
    assert "hibp" not in names
    assert "maigret" not in names


def test_target_classification_is_explicit():
    assert _target_kind("example.org")[0] == "domain"
    assert _target_kind("https://example.org/about")[0] == "url"
    assert _target_kind("analyst_handle")[0] == "username"
    assert _target_kind("analyst@example.org")[0] == "email"
    assert _target_kind("8.8.8.8")[0] == "ip"


def test_implemented_source_environment_names_match_collector_convention():
    by_id = {item.source_id: item for item in SOURCE_CATALOG}
    for source_id in ("virustotal", "otx", "securitytrails", "abuseipdb", "shodan", "censys", "misp"):
        assert by_id[source_id].auth_env
        assert all(name.startswith("SMART_INTEL_") for name in by_id[source_id].auth_env)


def test_identity_checks_use_common_workflow(monkeypatch):
    from smartintel import identity_checks
    from smartintel.workflow import run_identity_workflow
    def fake_check(kind, value, **options):
        return {"status": "completed", "identifier_type": kind, "value": value, "options": options}
    monkeypatch.setattr(identity_checks, "check_identity", fake_check)
    result = run_identity_workflow("username", "analyst_handle", max_sites=100)
    assert result["result"]["identifier_type"] == "username"
    assert result["result"]["options"]["process_timeout"] == 55
    assert any(event["type"] == "collector_completed" for event in result["events"])
    assert result["status"] == "completed"


def test_profile_metadata_fetch_uses_pinned_public_fetch(monkeypatch):
    from smartintel import identity_checks
    class FakeResponse:
        status_code = 200
        headers = {"Content-Type": "text/html; charset=utf-8"}
        content = b"<html><head><title>Public profile</title></head></html>"
        encoding = "utf-8"
        is_redirect = False
        is_permanent_redirect = False
        def raise_for_status(self): pass
    calls = []
    monkeypatch.setattr(identity_checks, "_public_profile_url", lambda url: url)
    monkeypatch.setattr("smartintel.collectors.passive._get_public_pinned",
                        lambda url: calls.append(url) or FakeResponse())
    result = identity_checks.fetch_public_profile_metadata("https://example.org/profile")
    assert calls == ["https://example.org/profile"]
    assert result["status"] == "completed"
    assert result["profile"]["title"] == "Public profile"


def test_selected_source_uses_workflow_registry(monkeypatch):
    from smartintel.collectors import all_in_one
    from smartintel.workflow import CollectorRegistry, CollectorSpec
    registry = CollectorRegistry()
    registry.register(CollectorSpec(
        name="demo_source",
        run=lambda target, context: {"title": "demo", "content": target, "source": "test"},
        target_types=("domain",),
    ))
    monkeypatch.setattr(all_in_one, "build_registry", lambda **kwargs: registry)
    result = all_in_one.run_selected("example.org", "demo_source")
    assert result["findings"][0]["content"] == "example.org"
    assert result["events"][0]["type"] == "workflow_started"
    assert result["events"][-1]["type"] == "workflow_completed"
