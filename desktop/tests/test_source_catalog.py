import pytest

from smartintel.source_catalog import (
    AdapterManager, AdapterUnavailable, SOURCE_CATALOG, list_sources,
    schema_fingerprint,
)


def test_catalog_is_explicit_about_implemented_vs_planned_sources():
    assert len(SOURCE_CATALOG) >= 40
    implemented = list_sources(status="implemented")
    planned = list_sources(status="planned")
    assert implemented
    assert planned
    assert all(item["status"] == "implemented" for item in implemented)
    assert all(item["status"] == "planned" for item in planned)


def test_catalog_can_filter_by_category():
    results = list_sources(category="sanctions")
    assert results
    assert all(item["category"] == "sanctions" for item in results)


def test_adapter_manager_retries_and_records_success():
    sleeps = []
    manager = AdapterManager(retries=2, base_delay=0.1, sleep=sleeps.append)
    calls = {"count": 0}

    def flaky():
        calls["count"] += 1
        if calls["count"] < 3:
            raise OSError("temporary")
        return {"records": [{"id": 1}]}

    assert manager.call("demo", flaky)["records"][0]["id"] == 1
    assert calls["count"] == 3
    assert len(sleeps) == 2
    assert manager.health_report()["demo"]["successes"] == 1


def test_adapter_manager_opens_circuit_after_repeated_failure():
    now = {"value": 100.0}
    manager = AdapterManager(
        retries=0, failure_threshold=2, cooldown_seconds=10,
        clock=lambda: now["value"], sleep=lambda _: None,
    )
    for _ in range(2):
        with pytest.raises(OSError):
            manager.call("down", lambda: (_ for _ in ()).throw(OSError("offline")))
    with pytest.raises(AdapterUnavailable):
        manager.call("down", lambda: "should not execute")
    now["value"] = 111.0
    assert manager.call("down", lambda: "recovered") == "recovered"


def test_adapter_manager_detects_schema_drift_without_silent_remapping():
    manager = AdapterManager(retries=0)
    manager.call("provider", lambda: {"data": [{"id": 1, "name": "A"}]})
    manager.call("provider", lambda: {"results": [{"uuid": "x"}]})
    assert manager.health_report()["provider"]["schema_drift"] is True
    assert schema_fingerprint({"x": 1}) != schema_fingerprint({"x": "1"})
