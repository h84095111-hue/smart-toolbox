# Smart Intel automation architecture

Smart Intel is being developed as an investigation workflow platform. The target
experience is: define a case and scope once, launch an investigation plan, and
let the workflow coordinate eligible collectors, preserve provenance, correlate
observations, and produce an evidence-linked report.

## Automation layers

1. **Workflow orchestration** — concurrent collectors, normalized findings,
   lifecycle events, isolated collector failures, bounded worker count, and an
   overall wait deadline.
2. **Collector plugins** — Python entry points in the
   `smartintel.collectors` group. A plugin exports
   `register_collectors(registry)` and registers one or more
   `CollectorSpec` instances.
3. **Evidence pipeline** — every finding should flow into a case-scoped evidence
   store with source URL, observed time, content hash, and audit event.
4. **Analysis pipeline** — entity extraction, deduplication, relationship graph,
   timeline, explainable scoring, and AI-generated pivot suggestions grounded
   in stored evidence.
5. **Operations** — CLI/REST entry points call the same workflow service as the
   desktop UI; schedulers and webhooks should use the same run/event model.

## Current implementation

`desktop/smartintel/workflow.py` provides a first orchestration foundation:
concurrent plugin execution, normalized results, per-collector error isolation,
workflow events, plugin registry, and an exact-target authorization gate for
collectors marked `active`. Passive collection is the default.

The existing all-in-one collector has not yet been migrated to this registry,
and the desktop UI, CLI, REST API, scheduler, evidence vault, and SIEM adapters
are not yet wired to this workflow service.

## Plugin contract

A plugin package declares an entry point, for example:

```toml
[project.entry-points."smartintel.collectors"]
example = "my_plugin:plugin"
```

The referenced object must expose:

```python
def register_collectors(registry):
    registry.register(CollectorSpec(
        name="example-public-source",
        description="Collects a public source",
        mode="passive",
        run=lambda target, context: [{"title": "Observation", "content": "..."}],
    ))
```

Plugins are trusted Python code and execute in-process. The registry is not a
security sandbox. Only install reviewed plugins. Collectors must set their own
network timeouts, respect provider terms and rate limits, and avoid collecting
data outside the case's documented purpose and scope.

## Automation safety defaults

- Passive public-source collection is the default.
- Active collectors are skipped unless the operator explicitly enables active
  mode and the exact target is present in the authorized-target list.
- No credential theft, leaked-password retrieval, exploitation, stealth,
  or uncontrolled scanning is part of this workflow engine.
- A workflow timeout cannot forcibly terminate a Python thread that is already
  running. Network collectors must use bounded request timeouts themselves.
- AI suggestions are leads for analyst review, not verified facts or autonomous
  authorization to expand scope.
