import pytest

from smartintel.workflow import (
    CollectorRegistry, CollectorSpec, ExecutionPolicy, run_workflow,
)


def test_workflow_runs_collectors_and_normalizes_results():
    registry = CollectorRegistry()
    registry.register(CollectorSpec("one", lambda target, ctx: {"title": "A", "content": target}))
    registry.register(CollectorSpec("two", lambda target, ctx: [{"title": "B"}, {"title": "C"}]))
    events = []
    result = run_workflow("example.org", registry, on_event=events.append)
    assert result["status"] == "completed"
    assert [row["title"] for row in result["findings"]] == ["A", "B", "C"]
    assert all(row["kind"] == "Passive OSINT" for row in result["findings"])
    assert events[-1]["type"] == "workflow_completed"


def test_workflow_isolates_collector_failures():
    registry = CollectorRegistry()
    registry.register(CollectorSpec("bad", lambda target, ctx: (_ for _ in ()).throw(RuntimeError("provider down"))))
    registry.register(CollectorSpec("good", lambda target, ctx: {"title": "still ran"}))
    result = run_workflow("example.org", registry)
    assert result["status"] == "completed_with_errors"
    assert result["findings"][0]["title"] == "still ran"
    assert result["failures"][0]["collector"] == "bad"


def test_active_collector_requires_opt_in_and_exact_scope():
    registry = CollectorRegistry()
    registry.register(CollectorSpec("active", lambda target, ctx: {"title": "active"}, mode="active"))
    denied = run_workflow("example.org", registry)
    assert denied["findings"] == []
    assert "authorization" in denied["skipped"][0]["reason"]
    allowed = run_workflow(
        "example.org", registry,
        policy=ExecutionPolicy(allow_active=True, authorized_targets=("example.org",)),
    )
    assert allowed["findings"][0]["title"] == "active"
    wrong_scope = run_workflow(
        "other.org", registry,
        policy=ExecutionPolicy(allow_active=True, authorized_targets=("example.org",)),
    )
    assert wrong_scope["findings"] == []


def test_workflow_rejects_empty_target_and_duplicate_plugin():
    registry = CollectorRegistry()
    registry.register(CollectorSpec("one", lambda target, ctx: []))
    with pytest.raises(ValueError):
        run_workflow(" ", registry)
    with pytest.raises(ValueError):
        registry.register(CollectorSpec("one", lambda target, ctx: []))
