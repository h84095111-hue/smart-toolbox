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
