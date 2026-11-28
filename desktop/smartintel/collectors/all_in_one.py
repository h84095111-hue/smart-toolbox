"""Orchestrate passive collectors through the shared workflow and source registry."""
from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from ..workflow import CollectorRegistry, CollectorSpec, ExecutionPolicy, run_workflow
from ..source_catalog import AdapterManager, SOURCE_CATALOG
from .passive import collect_domain, collect_ip, collect_website
from . import passive_sources as src
from ..hibp import check_email_breaches
from ..advanced_sources import opencorporates_search, courtlistener_search, opensanctions_search

_ADAPTER_MANAGER = AdapterManager(retries=1, base_delay=0.2, failure_threshold=3, cooldown_seconds=90.0)


def _target_kind(raw: str):
    email = bool(re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", raw))
    parsed = urlparse(raw if "://" in raw else "https://" + raw)
    is_url = ("://" in raw) or ("/" in raw)
    host = raw if email else (parsed.hostname if is_url else raw)
    if not host:
        raise ValueError("Could not identify a target host.")
    try:
        address = ipaddress.ip_address(host)
        if not address.is_global:
            raise ValueError("Only globally routable public IP addresses are supported.")
        return "ip", str(address), is_url
    except ValueError as exc:
        if "Only globally" in str(exc):
            raise
    if email:
        return "email", host, False
    if not is_url and "." not in host and re.fullmatch(r"@?[A-Za-z0-9_.-]{2,64}", host):
        return "username", host, False
    return ("url" if is_url else "domain"), host.lower().rstrip("."), is_url


def build_registry(*, misp_url: str = "", adapter_manager: AdapterManager | None = None) -> CollectorRegistry:
    """Build callable adapters from catalogue entries marked implemented."""
    manager = adapter_manager or _ADAPTER_MANAGER
    catalogue = {item.source_id: item for item in SOURCE_CATALOG}
    registry = CollectorRegistry()

    def add(source_id, fn, *, target_types, args=lambda target, context: (target,)):
        descriptor = catalogue.get(source_id)
        if descriptor is None or descriptor.status != "implemented":
            return

        def invoke(target, context):
            return manager.call(source_id, fn, *args(target, context))

        registry.register(CollectorSpec(
            name=source_id, run=invoke, description=descriptor.name,
            mode="passive", target_types=tuple(target_types), enabled=True,
        ))

    add("rdap", lambda target, kind: collect_ip(target) if kind == "ip" else collect_domain(target),
        target_types=("domain", "url", "ip"), args=lambda target, context: (target, context["target_type"]))
    add("public_website_metadata", collect_website, target_types=("url",),
        args=lambda target, context: (context["original_target"],))
    add("email_authorized_check_guidance", src.breach_check_guidance, target_types=("email",))
    add("hibp", check_email_breaches, target_types=("email",))
    add("opencorporates", opencorporates_search, target_types=("record_query",))
    add("courtlistener", courtlistener_search, target_types=("record_query",))
    add("opensanctions", opensanctions_search, target_types=("record_query",))
    add("crtsh", src.certificate_transparency, target_types=("domain", "url"))
    add("wayback", src.wayback, target_types=("domain", "url"),
        args=lambda target, context: (context.get("original_target", target),))
    add("virustotal", src.virustotal_domain, target_types=("domain", "url"))
    add("urlscan", src.urlscan_search, target_types=("domain", "url"))
    add("otx", src.otx_domain, target_types=("domain", "url"))
    add("securitytrails", src.passive_dns_history, target_types=("domain", "url"))
    add("gdelt", src.gdelt_news, target_types=("domain", "url"))
    add("abuseipdb", src.abuseipdb_ip, target_types=("ip",))
    add("shodan", src.shodan_host, target_types=("ip",))
    add("censys", src.censys_host, target_types=("ip",))
    add("public_username_reference", src.public_username_reference, target_types=("username",))

    if misp_url.strip():
        registry.register(CollectorSpec(
            name="misp_exact_ioc",
            run=lambda target, context: manager.call("misp", src.misp_search, misp_url.strip(), target),
            description="Exact IOC lookup in operator-configured MISP",
            target_types=("ip", "domain", "url", "email", "username"),
        ))
    return registry


def run_all(target, misp_url="", cancellation=None):
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Enter a domain, public IP address, email, username or website URL.")
    target_type, normalized, _ = _target_kind(raw)
    if target_type == "url":
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        if not parsed.hostname:
            raise ValueError("Could not identify a URL hostname.")
        normalized = parsed.hostname.lower().rstrip(".")

    result = run_workflow(
        normalized,
        build_registry(misp_url=misp_url),
        context={"original_target": raw, "target_type": target_type},
        target_type=target_type,
        policy=ExecutionPolicy(max_workers=6, timeout_seconds=60.0, allow_active=False),
        cancellation=cancellation,
    )
    failures = []
    skipped = [f"{row['collector']}: {row['reason']}" for row in result["skipped"]]
    friendly = {"crtsh": "Certificate transparency", "virustotal": "VirusTotal", "urlscan": "urlscan.io",
                "otx": "AlienVault OTX", "securitytrails": "SecurityTrails", "abuseipdb": "AbuseIPDB"}
    for row in result["failures"]:
        label = friendly.get(row["collector"], row["collector"])
        message = row["error"]
        if "API key" in message or "not configured" in message.lower() or "credential" in message.lower():
            skipped.append(f"{label}: provider key/configuration missing")
        else:
            failures.append(f"{label}: {message}")
    order = {spec.name: index for index, spec in enumerate(build_registry(misp_url=misp_url).list())}
    result["findings"].sort(key=lambda item: order.get(item.get("collector", ""), len(order)))
    if target_type == "email":
        skipped.append("Email checks are validation and authorized notification guidance only; no account discovery or credential-dump search is performed.")
    if target_type == "username":
        skipped.append("Username references are search starting points, not proof that an account exists or belongs to the subject.")
    return {
        "run_id": result["run_id"], "target": raw,
        "findings": result["findings"], "failures": failures,
        "skipped": skipped, "events": result["events"], "status": result["status"],
    }

def run_selected(target, source_id, misp_url="", cancellation=None):
    """Execute one catalogue-backed source through the shared workflow."""
    raw = (target or "").strip()
    if not raw:
        raise ValueError("Enter a lookup target.")
    if source_id in {"opencorporates","courtlistener","opensanctions"}:
        target_type, normalized = "record_query", raw
    else:
        target_type, normalized, _ = _target_kind(raw)
    if target_type == "url":
        parsed = urlparse(raw if "://" in raw else "https://" + raw)
        if not parsed.hostname:
            raise ValueError("Could not identify a URL hostname.")
        normalized = parsed.hostname.lower().rstrip(".")
    result = run_workflow(
        normalized,
        build_registry(misp_url=misp_url),
        context={"original_target": raw, "target_type": target_type},
        target_type=target_type,
        selected=(source_id,),
        policy=ExecutionPolicy(max_workers=1, timeout_seconds=45.0, allow_active=False),
        cancellation=cancellation,
    )
    return {
        "run_id": result["run_id"], "target": raw, "findings": result["findings"],
        "failures": result["failures"], "skipped": result["skipped"],
        "events": result["events"], "status": result["status"],
    }

