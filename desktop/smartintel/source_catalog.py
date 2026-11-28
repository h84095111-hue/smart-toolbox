"""Provider catalogue and adapter reliability primitives.

Catalogue entries describe integrations and their operational requirements. A
catalogue entry is not a claim that a connector is implemented or credentials
are available. Only entries marked "implemented" are callable by the app.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import Any, Callable, Iterable, Mapping
import json
import random
import time


@dataclass(frozen=True)
class SourceDescriptor:
    source_id: str
    name: str
    category: str
    access: str
    auth_env: tuple[str, ...] = ()
    status: str = "planned"
    notes: str = ""

    def __post_init__(self) -> None:
        if self.status not in {"implemented", "planned", "licensed", "manual"}:
            raise ValueError(f"Unsupported source status: {self.status}")
        if self.access not in {"public_api", "authenticated_api", "licensed_api", "public_web", "local"}:
            raise ValueError(f"Unsupported access type: {self.access}")


# Honest integration roadmap: planned/licensed entries are metadata only.
SOURCE_CATALOG: tuple[SourceDescriptor, ...] = (
    SourceDescriptor("misp", "MISP", "threat_intelligence", "authenticated_api", ("SMART_INTEL_MISP_API_KEY",), "implemented", "Operator-managed instance URL required"),
    SourceDescriptor("crtsh", "crt.sh", "certificate_transparency", "public_api", status="implemented"),
    SourceDescriptor("wayback", "Internet Archive Wayback", "web_history", "public_api", status="implemented"),
    SourceDescriptor("virustotal", "VirusTotal", "threat_intelligence", "authenticated_api", ("SMART_INTEL_VIRUSTOTAL_API_KEY",), "implemented"),
    SourceDescriptor("urlscan", "urlscan.io", "web_analysis", "public_api", status="implemented"),
    SourceDescriptor("otx", "AlienVault OTX", "threat_intelligence", "authenticated_api", ("SMART_INTEL_OTX_API_KEY",), "implemented"),
    SourceDescriptor("securitytrails", "SecurityTrails", "passive_dns", "authenticated_api", ("SMART_INTEL_SECURITYTRAILS_API_KEY",), "implemented"),
    SourceDescriptor("abuseipdb", "AbuseIPDB", "ip_reputation", "authenticated_api", ("SMART_INTEL_ABUSEIPDB_API_KEY",), "implemented"),
    SourceDescriptor("shodan", "Shodan", "ip_metadata", "authenticated_api", ("SMART_INTEL_SHODAN_API_KEY",), "implemented", "Existing host metadata only"),
    SourceDescriptor("censys", "Censys", "ip_metadata", "authenticated_api", ("SMART_INTEL_CENSYS_API_KEY",), "implemented", "Existing host metadata only"),
    SourceDescriptor("hibp", "Have I Been Pwned", "breach_notification", "authenticated_api", ("SMART_INTEL_HIBP_API_KEY",), notes="Authenticated, terms-compliant account/domain workflows; no credential dumps"),
    SourceDescriptor("opencorporates", "OpenCorporates", "corporate_records", "authenticated_api", ("OPENCORPORATES_API_KEY",)),
    SourceDescriptor("opensanctions", "OpenSanctions", "sanctions_pep", "public_api"),
    SourceDescriptor("company_house", "UK Companies House", "corporate_records", "authenticated_api", ("COMPANIES_HOUSE_API_KEY",)),
    SourceDescriptor("sec_edgar", "SEC EDGAR", "corporate_filings", "public_api"),
    SourceDescriptor("gleif", "GLEIF LEI", "corporate_records", "public_api"),
    SourceDescriptor("world_bank_sanctions", "World Bank Debarred Firms", "sanctions", "public_web"),
    SourceDescriptor("eu_sanctions", "EU Sanctions Map", "sanctions", "public_web"),
    SourceDescriptor("ofac", "OFAC Sanctions Search", "sanctions", "public_web"),
    SourceDescriptor("uk_sanctions", "UK Sanctions List", "sanctions", "public_web"),
    SourceDescriptor("courtlistener", "CourtListener", "court_records", "authenticated_api", ("COURTLISTENER_API_TOKEN",)),
    SourceDescriptor("pacer", "PACER", "court_records", "licensed_api", ("PACER_CREDENTIALS",), "licensed", "Fees and account terms apply"),
    SourceDescriptor("whoisxml", "WhoisXML API", "whois_history", "licensed_api", ("WHOISXML_API_KEY",), "licensed"),
    SourceDescriptor("domain_tools", "DomainTools", "whois_history", "licensed_api", ("DOMAINTOOLS_API_KEY",), "licensed"),
    SourceDescriptor("risk_iq", "Recorded Future", "threat_intelligence", "licensed_api", ("RECORDED_FUTURE_API_KEY",), "licensed"),
    SourceDescriptor("greynoise", "GreyNoise", "ip_intelligence", "authenticated_api", ("GREYNOISE_API_KEY",)),
    SourceDescriptor("spur", "Spur", "ip_intelligence", "licensed_api", ("SPUR_API_KEY",), "licensed"),
    SourceDescriptor("rdap", "RDAP", "registration", "public_api", status="implemented"),
    SourceDescriptor("dnsdb", "Farsight DNSDB", "passive_dns", "licensed_api", ("DNSDB_API_KEY",), "licensed"),
    SourceDescriptor("passivetotal", "RiskIQ PassiveTotal", "passive_dns", "licensed_api", ("PASSIVETOTAL_API_KEY",), "licensed"),
    SourceDescriptor("maigret", "Maigret", "username_presence", "local", status="planned", notes="CLI integration is not yet routed through the workflow engine"),
    SourceDescriptor("public_username_reference", "Public username reference links", "username_presence", "local", status="implemented"),
    SourceDescriptor("sherlock", "Sherlock", "username_presence", "local"),
    SourceDescriptor("whoxy", "Whoxy", "whois_history", "authenticated_api", ("WHOXY_API_KEY",)),
    SourceDescriptor("google_cse", "Google Programmable Search", "web_search", "authenticated_api", ("GOOGLE_CSE_API_KEY", "GOOGLE_CSE_CX")),
    SourceDescriptor("bing_search", "Bing Web Search", "web_search", "authenticated_api", ("BING_SEARCH_API_KEY",)),
    SourceDescriptor("telegram_api", "Telegram API", "social_monitoring", "authenticated_api", ("TELEGRAM_API_ID", "TELEGRAM_API_HASH")),
    SourceDescriptor("reddit", "Reddit API", "social_monitoring", "authenticated_api", ("REDDIT_CLIENT_ID", "REDDIT_CLIENT_SECRET")),
    SourceDescriptor("mastodon", "Mastodon API", "social_monitoring", "public_api"),
    SourceDescriptor("gdelt", "GDELT", "news_monitoring", "public_api", status="implemented"),
    SourceDescriptor("public_website_metadata", "Public website metadata", "web_analysis", "public_web", status="implemented"),
    SourceDescriptor("email_authorized_check_guidance", "Authorized breach-check guidance", "breach_notification", "local", status="implemented"),
    SourceDescriptor("opensky", "OpenSky Network", "aviation", "authenticated_api", ("OPENSKY_CLIENT_ID", "OPENSKY_CLIENT_SECRET")),
    SourceDescriptor("adsbexchange", "ADS-B Exchange", "aviation", "licensed_api", ("ADSBX_API_KEY",), "licensed"),
    SourceDescriptor("marinetraffic", "MarineTraffic", "maritime", "licensed_api", ("MARINETRAFFIC_API_KEY",), "licensed"),
    SourceDescriptor("vesselfinder", "VesselFinder", "maritime", "licensed_api", ("VESSELFINDER_API_KEY",), "licensed"),
    SourceDescriptor("exiftool", "ExifTool", "document_metadata", "local"),
    SourceDescriptor("tesseract", "Tesseract OCR", "document_analysis", "local"),
    SourceDescriptor("yandex_images", "Yandex Images", "reverse_image", "public_web", status="manual", notes="Operator-mediated search link; no automated face identification"),
    SourceDescriptor("google_lens", "Google Lens", "reverse_image", "public_web", status="manual", notes="Operator-mediated search link"),
    SourceDescriptor("hibp_domain", "HIBP Domain Search", "breach_notification", "authenticated_api", ("SMART_INTEL_HIBP_API_KEY",), notes="Requires domain verification"),
)


def list_sources(*, category: str | None = None, status: str | None = None) -> list[dict[str, Any]]:
    """Return source metadata; never imply planned sources are operational."""
    items = SOURCE_CATALOG
    if category:
        items = tuple(item for item in items if item.category == category)
    if status:
        items = tuple(item for item in items if item.status == status)
    return [asdict(item) for item in items]


@dataclass
class AdapterHealth:
    failures: int = 0
    successes: int = 0
    circuit_open_until: float = 0.0
    last_error: str = ""
    last_success_at: str = ""
    last_schema_fingerprint: str = ""
    schema_drift: bool = False


class AdapterUnavailable(RuntimeError):
    pass


class AdapterManager:
    """Retry transient failures, circuit-break unhealthy providers, detect drift.

    Schema fingerprints are based on stable JSON key/type shapes. Drift is
    reported, not auto-remapped: silent adaptation could corrupt evidence.
    """

    def __init__(
        self,
        *,
        retries: int = 2,
        base_delay: float = 0.25,
        failure_threshold: int = 3,
        cooldown_seconds: float = 60.0,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if retries < 0 or base_delay < 0 or failure_threshold < 1 or cooldown_seconds <= 0:
            raise ValueError("Invalid adapter reliability settings")
        self.retries = retries
        self.base_delay = base_delay
        self.failure_threshold = failure_threshold
        self.cooldown_seconds = cooldown_seconds
        self.sleep = sleep
        self.clock = clock
        self.health: dict[str, AdapterHealth] = {}

    def call(self, source_id: str, adapter: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:
        state = self.health.setdefault(source_id, AdapterHealth())
        if state.circuit_open_until > self.clock():
            raise AdapterUnavailable(f"{source_id} circuit is open after repeated failures")
        last_error: Exception | None = None
        for attempt in range(self.retries + 1):
            try:
                result = adapter(*args, **kwargs)
                state.successes += 1
                state.failures = 0
                state.circuit_open_until = 0.0
                state.last_error = ""
                state.last_success_at = datetime.now(timezone.utc).isoformat()
                fingerprint = schema_fingerprint(result)
                if state.last_schema_fingerprint and fingerprint != state.last_schema_fingerprint:
                    state.schema_drift = True
                state.last_schema_fingerprint = fingerprint
                return result
            except Exception as exc:
                last_error = exc
                if attempt < self.retries:
                    self.sleep(self.base_delay * (2 ** attempt) + random.uniform(0, self.base_delay / 4 if self.base_delay else 0))
        state.failures += 1
        state.last_error = (str(last_error) or type(last_error).__name__)[:500]
        if state.failures >= self.failure_threshold:
            state.circuit_open_until = self.clock() + self.cooldown_seconds
        raise last_error  # type: ignore[misc]

    def health_report(self) -> dict[str, dict[str, Any]]:
        return {
            source_id: {
                "failures": state.failures,
                "successes": state.successes,
                "circuit_open": state.circuit_open_until > self.clock(),
                "last_error": state.last_error,
                "last_success_at": state.last_success_at,
                "schema_drift": state.schema_drift,
            }
            for source_id, state in self.health.items()
        }


def schema_fingerprint(value: Any) -> str:
    """Hash a deterministic structural signature, not provider response values."""
    def shape(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {str(key): shape(val) for key, val in sorted(item.items(), key=lambda pair: str(pair[0]))}
        if isinstance(item, list):
            return {"list_item": shape(item[0]) if item else "empty"}
        if item is None:
            return "null"
        if isinstance(item, bool):
            return "bool"
        if isinstance(item, (int, float)):
            return "number"
        return type(item).__name__
    payload = json.dumps(shape(value), sort_keys=True, separators=(",", ":"))
    return sha256(payload.encode("utf-8")).hexdigest()
