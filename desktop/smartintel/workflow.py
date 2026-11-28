"""Process-isolated, policy-aware workflow runner.

Collector plugins are trusted installed Python code, not a sandbox. Each job
runs in its own process so timeout/cancellation can terminate it reliably.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from importlib.metadata import entry_points
from typing import Any, Callable, Iterable, Mapping
import multiprocessing as mp
import threading
import time
import uuid
import os
import signal
import subprocess

Collector = Callable[[str, Mapping[str, Any]], Any]


class CancellationToken:
    """Thread-safe signal used by GUI controllers to stop a running workflow."""
    def __init__(self):
        self._event = threading.Event()

    def cancel(self):
        self._event.set()

    @property
    def cancelled(self):
        return self._event.is_set()


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
        """Load explicitly installed Python entry-point plugins (trusted code)."""
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


def _collector_child(payload: bytes, sender) -> None:
    """Spawn target; cloudpickle is used only for serializing trusted callables."""
    if os.name != "nt":
        try:
            os.setsid()
        except OSError:
            pass
    try:
        import cloudpickle
        fn, target, context = cloudpickle.loads(payload)
        try:
            value = fn(target, context)
            response = {"ok": True, "value": value}
        except BaseException as exc:
            response = {"ok": False, "error": (exc.__class__.__name__, str(exc)[:1000])}
        sender.send_bytes(cloudpickle.dumps(response))
    except BaseException as exc:
        try:
            import cloudpickle
            sender.send_bytes(cloudpickle.dumps({"ok": False, "error": (exc.__class__.__name__, str(exc)[:1000])}))
        except Exception:
            pass
    finally:
        try:
            sender.close()
        except Exception:
            pass


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
        row.setdefault("collector", spec.name)
        row.setdefault("kind", "Passive OSINT" if spec.mode == "passive" else "Authorized active collection")
        normalized.append(row)
    return normalized


def _stop_process(process):
    if process is None:
        return
    if os.name == "nt":
        try:
            subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"],
                           capture_output=True, timeout=5, check=False)
        except Exception:
            pass
        if process.is_alive():
            process.terminate()
    else:
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except (ProcessLookupError, PermissionError, OSError):
            if process.is_alive():
                process.terminate()
    process.join(timeout=1.0)
    if process.is_alive():
        if os.name == "nt" and hasattr(process, "kill"):
            process.kill()
        else:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except (ProcessLookupError, PermissionError, OSError):
                if hasattr(process, "kill"):
                    process.kill()
        process.join(timeout=1.0)
    if process.is_alive():
        raise RuntimeError("Collector process did not stop after terminate/kill request.")


def run_workflow(
    target: str,
    registry: CollectorRegistry,
    *,
    context: Mapping[str, Any] | None = None,
    policy: ExecutionPolicy | None = None,
    selected: Iterable[str] | None = None,
    target_type: str | None = None,
    on_event: Callable[[dict[str, Any]], None] | None = None,
    cancellation: CancellationToken | None = None,
) -> dict[str, Any]:
    """Run eligible collectors in isolated processes with hard timeouts.

    Cancellation terminates all in-flight collector processes; no collector
    thread is left running after the workflow returns. Child processes are
    trusted code execution, not a security sandbox.
    """
    target = (target or "").strip()
    if not target:
        raise ValueError("An investigation target is required")
    policy = policy or ExecutionPolicy()
    if policy.max_workers < 1 or policy.timeout_seconds <= 0:
        raise ValueError("Workflow limits must be positive")
    context_data = dict(context or {})
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
        elif spec.mode == "active" and not (policy.allow_active and target in policy.authorized_targets):
            skipped.append({"collector": spec.name, "reason": "active collection requires explicit opt-in and exact target authorization"})
        else:
            eligible.append(spec)

    emit({"type": "workflow_started", "target": target, "collector_count": len(eligible)})
    try:
        import cloudpickle
    except ImportError as exc:
        raise RuntimeError("Workflow process isolation requires cloudpickle. Reinstall desktop requirements.") from exc

    mp_context = mp.get_context("spawn")
    waiting = list(eligible)
    running: dict[str, dict[str, Any]] = {}
    deadline = time.monotonic() + policy.timeout_seconds

    def start_job(spec):
        receiver, sender = mp_context.Pipe(duplex=False)
        payload = cloudpickle.dumps((spec.run, target, context_data))
        process = mp_context.Process(target=_collector_child, args=(payload, sender),
                                     name="smartintel-" + spec.name[:40])
        process.daemon = False
        process.start()
        sender.close()
        running[spec.name] = {"spec": spec, "process": process, "receiver": receiver}
        emit({"type": "collector_started", "collector": spec.name})

    def stop_job(name, reason):
        item = running.pop(name)
        try:
            _stop_process(item["process"])
        finally:
            item["receiver"].close()
            item["process"].close()
        emit({"type": "collector_cancelled" if reason == "cancelled" else "collector_timed_out",
              "collector": name})
        if reason == "timeout":
            failures.append({"collector": name, "error": f"workflow timeout after {policy.timeout_seconds:g}s; collector process terminated"})
    
    try:
        while waiting or running:
            if cancellation and cancellation.cancelled:
                for name in list(running):
                    stop_job(name, "cancelled")
                waiting.clear()
                break
            while waiting and len(running) < policy.max_workers:
                spec = waiting.pop(0)
                try:
                    start_job(spec)
                except Exception as exc:
                    failures.append({"collector": spec.name, "error": str(exc)[:500]})
                    emit({"type": "collector_failed", "collector": spec.name, "error": str(exc)[:500]})
            for name, item in list(running.items()):
                receiver, process, spec = item["receiver"], item["process"], item["spec"]
                if receiver.poll():
                    try:
                        reply = cloudpickle.loads(receiver.recv_bytes())
                        if reply.get("ok"):
                            rows = _normalize_result(spec, reply.get("value"))
                            findings.extend(rows)
                            emit({"type": "collector_completed", "collector": name, "finding_count": len(rows)})
                        else:
                            cls, message = reply.get("error", ("CollectorError", "Collector failed"))
                            message = (message or cls)[:500]
                            failures.append({"collector": name, "error": message})
                            emit({"type": "collector_failed", "collector": name, "error": message})
                    except Exception as exc:
                        failures.append({"collector": name, "error": f"invalid collector response: {exc}"})
                        emit({"type": "collector_failed", "collector": name, "error": str(exc)[:500]})
                    process.join(timeout=0.5)
                    running.pop(name)
                    receiver.close()
                    process.close()
                elif not process.is_alive():
                    process.join(timeout=0.1)
                    failures.append({"collector": name, "error": f"collector process exited with code {process.exitcode} without a result"})
                    emit({"type": "collector_failed", "collector": name, "error": "collector process exited unexpectedly"})
                    running.pop(name)
                    receiver.close()
                    process.close()
            if time.monotonic() >= deadline:
                for name in list(running):
                    stop_job(name, "timeout")
                for spec in waiting:
                    failures.append({"collector": spec.name, "error": "workflow deadline reached before collector started"})
                    emit({"type": "collector_timed_out", "collector": spec.name})
                waiting.clear()
                break
            time.sleep(0.025)
    finally:
        for name in list(running):
            stop_job(name, "cancelled")

    was_cancelled = bool(cancellation and cancellation.cancelled)
    status = "cancelled" if was_cancelled else ("completed_with_errors" if failures else "completed")
    emit({"type": "workflow_completed", "status": status, "finding_count": len(findings)})
    return {
        "run_id": run_id, "target": target, "started_at": started,
        "finished_at": datetime.now(timezone.utc).isoformat(), "status": status,
        "findings": findings, "failures": failures, "skipped": skipped, "events": events,
    }


def run_identity_workflow(identifier_type: str, value: str, *, cancellation: CancellationToken | None = None, **options: Any) -> dict[str, Any]:
    """Run one analyst-requested identity check through the common workflow."""
    from .identity_checks import check_identity

    kind = (identifier_type or "").strip().lower()
    if kind not in {"username", "email", "phone", "profile_url"}:
        raise ValueError("Unsupported identity check type.")
    target = (value or "").strip()
    if not target:
        raise ValueError("An identity value is required.")
    spec_name = "identity_check_" + kind

    def invoke(target_value: str, context: Mapping[str, Any]) -> Any:
        settings = dict(context.get("options", {}))
        if kind == "username":
            settings.setdefault("process_timeout", 55)
        return check_identity(kind, target_value, **settings)

    registry = CollectorRegistry()
    registry.register(CollectorSpec(
        name=spec_name, run=invoke,
        description=f"Analyst-requested {kind} identity check",
        mode="active" if kind == "username" else "passive", target_types=(kind,),
    ))
    active = kind == "username"
    workflow = run_workflow(
        target, registry, context={"options": options},
        policy=ExecutionPolicy(max_workers=1, timeout_seconds=60.0 if active else 20.0,
                               allow_active=active, authorized_targets=(target,) if active else ()),
        selected=(spec_name,), target_type=kind, cancellation=cancellation,
    )
    payload = workflow["findings"][0] if workflow["findings"] else {}
    return {"result": payload, "run_id": workflow["run_id"], "events": workflow["events"],
            "status": workflow["status"], "failures": workflow["failures"], "skipped": workflow["skipped"]}
