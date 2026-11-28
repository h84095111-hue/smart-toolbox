import multiprocessing
import time
from pathlib import Path
import pytest

from smartintel.workflow import (
    CancellationToken, CollectorRegistry, CollectorSpec, ExecutionPolicy, run_workflow,
)
from smartintel.storage import Store
from smartintel.identity_graph import GraphNode, GraphEdge, IdentityGraph, apply_graph_aliases
from smartintel.network import validate_proxy_url, proxy_label
from smartintel.image_intel import hamming_distance


def _slow_collector(target, context):
    time.sleep(8)
    return {"title": "should have been stopped"}


def test_workflow_hard_cancellation_terminates_running_process():
    registry = CollectorRegistry()
    registry.register(CollectorSpec("slow", _slow_collector))
    token = CancellationToken()

    def stop_after_start(event):
        if event["type"] == "collector_started":
            time.sleep(0.35)
            token.cancel()

    result = run_workflow(
        "example.org", registry,
        policy=ExecutionPolicy(max_workers=1, timeout_seconds=15),
        cancellation=token, on_event=stop_after_start,
    )
    assert result["status"] == "cancelled"
    assert any(item["type"] == "collector_cancelled" for item in result["events"])
    assert not [child for child in multiprocessing.active_children()
                if child.name.startswith("smartintel-slow")]


def test_workflow_hard_timeout_records_terminated_collector():
    registry = CollectorRegistry()
    registry.register(CollectorSpec("slow", _slow_collector))
    result = run_workflow("example.org", registry,
                          policy=ExecutionPolicy(max_workers=1, timeout_seconds=0.2))
    assert result["status"] == "completed_with_errors"
    assert result["failures"][0]["collector"] == "slow"
    assert "terminated" in result["failures"][0]["error"]


def test_local_accounts_hash_passwords_and_limit_case_access(tmp_path):
    store = Store(tmp_path / "accounts.sqlite3")
    owner = store.create_user("case_admin", "a-very-long-password", "admin")
    viewer = store.create_user("viewer_one", "another-long-password", "viewer")
    assert store.authenticate_user("case_admin", "a-very-long-password")["id"] == owner
    assert store.authenticate_user("case_admin", "wrong-password") is None
    case_id = store.create_case("Private case", owner_id=owner)
    store.add_case_member(case_id, viewer, "viewer")
    viewer_user = store.authenticate_user("viewer_one", "another-long-password")
    assert store.user_case_role(case_id, viewer_user) == "viewer"
    assert store.cases_for_user(viewer_user)[0]["id"] == case_id
    assert store.cases_for_user({"id": owner, "role": "admin"})[0]["id"] == case_id


def test_monitor_schedule_is_persistent_and_minimum_interval_enforced(tmp_path):
    store = Store(tmp_path / "monitor.sqlite3")
    user = store.create_user("analyst_one", "long-enough-password", "analyst")
    case_id = store.create_case("Monitoring", owner_id=user)
    schedule_id = store.add_monitor_schedule(case_id, "example.org", 3600, user)
    assert any(row["id"] == schedule_id for row in store.due_monitor_schedules())
    assert store.monitor_schedules(case_id)[0]["target"] == "example.org"
    with pytest.raises(ValueError):
        store.add_monitor_schedule(case_id, "example.org", 300, user)


def test_graph_alias_merge_preserves_evidence_and_coalesces_edges():
    nodes = [
        GraphNode("email:a", "email", "a@example.org", ["e1"]),
        GraphNode("email:b", "email", "alias@example.org", ["e2"]),
        GraphNode("source:s", "source", "Public source", ["e1", "e2"]),
    ]
    edges = [
        GraphEdge("email:a", "source:s", "observed_in", ["e1"], "first observation"),
        GraphEdge("email:b", "source:s", "observed_in", ["e2"], "second observation"),
    ]
    graph = IdentityGraph(nodes, edges, "2026-01-01T00:00:00+00:00")
    merged = apply_graph_aliases(graph, [{"alias_node_id": "email:b", "canonical_node_id": "email:a"}])
    email = next(node for node in merged.nodes if node.id == "email:a")
    assert set(email.evidence_ids) == {"e1", "e2"}
    assert len([node for node in merged.nodes if node.kind == "email"]) == 1
    assert len([edge for edge in merged.edges if edge.relation == "observed_in"]) == 1
    assert set(merged.edges[0].evidence_ids) == {"e1", "e2"}


def test_graph_alias_cycles_are_rejected():
    graph = IdentityGraph(
        [GraphNode("a", "email", "a", ["1"]), GraphNode("b", "email", "b", ["2"])],
        [], "2026-01-01T00:00:00+00:00",
    )
    with pytest.raises(ValueError, match="cycle"):
        apply_graph_aliases(graph, [
            {"alias_node_id": "a", "canonical_node_id": "b"},
            {"alias_node_id": "b", "canonical_node_id": "a"},
        ])


def test_proxy_validation_is_opt_in_and_supports_tor_socks5():
    assert validate_proxy_url("") == ""
    assert validate_proxy_url("socks5://127.0.0.1:9050") == "socks5://127.0.0.1:9050"
    assert "Tor SOCKS5" in proxy_label("socks5://127.0.0.1:9050")
    with pytest.raises(ValueError):
        validate_proxy_url("ftp://proxy.example.org:21")


def test_perceptual_hash_distance_is_bounded():
    assert hamming_distance("0000000000000000", "0000000000000000") == 0
    assert hamming_distance("0000000000000000", "ffffffffffffffff") == 64
    with pytest.raises(ValueError):
        hamming_distance("invalid", "0000000000000000")


def test_hibp_adapter_returns_metadata_only(monkeypatch):
    from smartintel import hibp
    class Response:
        status_code = 200
        def json(self):
            return [{"Name": "ExampleBreach", "Title": "Example Breach",
                     "BreachDate": "2024-01-01", "PwnCount": 1234,
                     "DataClasses": ["Email addresses"], "IsVerified": True}]
        def raise_for_status(self):
            raise AssertionError("Unexpected status")
    monkeypatch.setattr(hibp, "get_api_key", lambda provider: "a" * 32)
    monkeypatch.setattr(hibp.requests, "get", lambda *args, **kwargs: Response())
    result = hibp.check_email_breaches("person@example.org")
    assert result["breach_count"] == 1
    assert result["breaches"][0]["name"] == "ExampleBreach"
    assert "password" not in str(result).casefold()


def test_signed_export_verifies_and_detects_tampering(tmp_path, monkeypatch):
    from smartintel import signing
    secrets = {}
    monkeypatch.setattr(signing, "get_api_key", lambda provider: secrets.get(provider))
    monkeypatch.setattr(signing, "save_api_key", lambda provider, value: secrets.__setitem__(provider, value))
    bundle = tmp_path / "case.signed.zip"
    result = signing.signed_export({"name": "Case"}, [{"id": "ev-1", "content": "observation"}], bundle)
    assert result["timestamp_status"] == "not_requested"
    assert signing.verify_signed_export(bundle)["valid"] is True
