"""Concurrent, policy-aware workflow runner for Smart Intel collectors.

Plugins are trusted Python code installed by the operator. The runner coordinates
them; it is not a sandbox. Network collection should default to passive sources.
"""
from __future__ import annotations

from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import entry_points
from typing import Any, Callable, Iterable, Mapping
import uuid


Collector = Callable[[str, Mapping[str, Any]], Any]


@dataclass(frozen=True)
class CollectorSpec:
    name: str
    run: Collector
    description: str = ""
    mode: str = "passive"
    target_types: tuple[str, ...] = ("domain", "ip", "url", "username", "email")
    enabled: bool = True

    def __post_init__(self) -> None:
        if not self.name.strip():
            raise ValueError("Collector name cannot be empty")
        if self.mode not in {"passive", "active"}:
            raise ValueError("Collector mode must be 'passive' or 'active'")


@dataclass(frozen=True)
class ExecutionPolicy:
    """Safe defaults; active collectors require explicit opt-in and exact scope."""
    max_workers: int = 6
    timeout_seconds: float = 45.0
    allow_active: bool = False
    authorized_targets: tuple[str, ...] = ()


@dataclass
class CollectorRegistry:
    _collectors: dict[str, CollectorSpec] = field(default_factory=dict)

    def register(self, spec: CollectorSpec, *, replace: bool = False) -> None:
        if spec.name in self._collectors and not replace:
            raise ValueError(f"Collector already registered: {spec.name}")
        self._collectors[spec.name] = spec

    def get(self, name: str) -> CollectorSpec:
        return self._collectors[name]

    def list(self) -> list[CollectorSpec]:
        return list(self._collectors.values())

    def load_entry_points(self, group: str = "smartintel.collectors") -> list[str]:
        """Load explicitly installed Python entry-point plugins.

        Entry points execute trusted code during loading. Install plugins only
        from sources the operator trusts.
        """
        loaded: list[str] = []
        discovered = entry_points()
        selected = discovered.select(group=group) if hasattr(discovered, "select") else discovered.get(group, [])
        for point in selected:
            plugin = point.load()
            register = getattr(plugin, "register_collectors", None)
            if not callable(register):
                raise TypeError(f"Plugin {point.name!r} has no register_collectors(registry) function")
            register(self)
            loaded.append(point.name)
        return loaded


def _normalize_result(spec: CollectorSpec, value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    values = value if isinstance(value, list) else [value]
    normalized: list[dict[str, Any]] = []
    for item in values:
        if isinstance(item, dict):
            row = dict(item)
        else:
            row = {
                "title": getattr(item, "title", spec.name),
                "content": getattr(item, "value", str(item)),
                "source": getattr(item, "source", spec.name),
                "url": getattr(item, "url", ""),
                "confidence": getattr(item, "confidence", "Medium"),
            }
        row.setdefault("source", spec.name)
        row.setdefault("kind", "Passive OSINT" if spec.mode == "passive" else "Authorized active collection")
        normalized.append(row)
    return normalized


def run_workflow(
    target: str,
    registry: CollectorRegistry,
    *,
    context: Mapping[str, Any] | None = None,
    policy: ExecutionPolicy | None = None,
    selected: Iterable[str] | None = None,
    target_type: str | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
) -> dict[str, Any]:
    """Run eligible collectors concurrently and return a normalized case payload.

    A timeout stops waiting and cancels work that has not started. Python cannot
    forcibly stop an already-running collector thread; collectors must enforce
    their own network timeouts.
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("An investigation target is required")
    policy = policy or ExecutionPolicy()
    if policy.max_workers < 1 or policy.timeout_seconds <= 0:
        raise ValueError("Workflow limits must be positive")
    context = dict(context or {})
    requested = set(selected) if selected is not None else None
    run_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc).isoformat()
    events: list[dict[str, Any]] = []
    findings: list[dict[str, Any]] = []
    failures: list[dict[str, str]] = []
    skipped: list[dict[str, str]] = []

    def emit(event: dict[str, Any]) -> None:
        event = {"run_id": run_id, "timestamp": datetime.now(timezone.utc).isoformat(), **event}
        events.append(event)
        if on_event:
            on_event(event)

    eligible: list[CollectorSpec] = []
    for spec in registry.list():
        if requested is not None and spec.name not in requested:
            continue
        if not spec.enabled:
            skipped.append({"collector": spec.name, "reason": "disabled"})
        elif target_type and target_type not in spec.target_types:
            skipped.append({"collector": spec.name, "reason": f"not applicable to {target_type}"})
        elif spec.mode == "active" and not (
            policy.allow_active and target in policy.authorized_targets
        ):
            skipped.append({"collector": spec.name, "reason": "active collection requires explicit opt-in and exact target authorization"})
        else:
            eligible.append(spec)

    emit({"type": "workflow_started", "target": target, "collector_count": len(eligible)})
    futures: dict[Any, CollectorSpec] = {}
    executor = ThreadPoolExecutor(max_workers=policy.max_workers, thread_name_prefix="smartintel")
    try:
        for spec in eligible:
            emit({"type": "collector_started", "collector": spec.name})
            futures[executor.submit(spec.run, target, context)] = spec
        pending = set(futures)
        deadline = __import__("time").monotonic() + policy.timeout_seconds
        while pending:
            remaining = deadline - __import__("time").monotonic()
            if remaining <= 0:
                break
            done, pending = wait(pending, timeout=remaining, return_when=FIRST_COMPLETED)
            for future in done:
                spec = futures[future]
                try:
                    rows = _normalize_result(spec, future.result())
                    findings.extend(rows)
                    emit({"type": "collector_completed", "collector": spec.name, "finding_count": len(rows)})
                except Exception as exc:
                    message = str(exc).strip() or exc.__class__.__name__
                    failures.append({"collector": spec.name, "error": message[:500]})
                    emit({"type": "collector_failed", "collector": spec.name, "error": message[:500]})
        for future in pending:
            spec = futures[future]
            future.cancel()
            failures.append({"collector": spec.name, "error": f"workflow timeout after {policy.timeout_seconds:g}s; running thread may finish in background"})
            emit({"type": "collector_timed_out", "collector": spec.name})
    finally:
        executor.shutdown(wait=False, cancel_futures=True)

    status = "completed_with_errors" if failures else "completed"
    emit({"type": "workflow_completed", "status": status, "finding_count": len(findings)})
    return {
        "run_id": run_id,
        "target": target,
        "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "findings": findings,
        "failures": failures,
        "skipped": skipped,
        "events": events,
    }
