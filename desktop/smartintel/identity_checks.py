"""No-paid-API identity checks using public, locally installed OSINT tools.

Username checks are delegated to Maigret's maintained public-site database.
Email and phone checks are deliberately limited to syntax, DNS/public numbering
metadata, and user-directed public search links; they do not probe private
accounts, perform SMTP mailbox enumeration, or access breach dumps.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import quote, urlparse
import json
import re
import shutil
import subprocess
import tempfile
import time
import socket


@dataclass
class IdentityFinding:
    identifier_type: str
    value: str
    status: str
    source: str
    url: str = ""
    title: str = ""
    details: str = ""
    confidence: str = "low"

    def to_dict(self) -> dict[str, str]:
        return asdict(self)


def _valid_username(value: str) -> str:
    value = (value or "").strip().lstrip("@")
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", value):
        raise ValueError("Username must be 2-64 characters: letters, numbers, dot, underscore or hyphen.")
    return value


def _walk_json(value: Any) -> Iterable[dict[str, Any]]:
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk_json(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk_json(child)


def parse_maigret_report(path: str | Path, username: str) -> list[IdentityFinding]:
    """Normalize Maigret JSON output across its simple/NDJSON report layouts."""
    report = Path(path)
    if not report.exists():
        return []
    text = report.read_text(encoding="utf-8", errors="replace").strip()
    if not text:
        return []
    try:
        payload: Any = json.loads(text)
    except json.JSONDecodeError:
        payload = []
        for line in text.splitlines():
            try:
                payload.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    findings: list[IdentityFinding] = []
    seen: set[tuple[str, str]] = set()
    for row in _walk_json(payload):
        status = str(row.get("status", "")).lower()
        # Maigret JSON may store status as an enum-like object or string.
        if isinstance(row.get("status"), dict):
            status = str(row["status"].get("name", row["status"].get("status", ""))).lower()
        found = status in {"claimed", "found", "exists", "true"} or row.get("is_found") is True
        if not found:
            continue
        url = str(row.get("url_user") or row.get("url") or row.get("profile_url") or "")
        site = str(row.get("sitename") or row.get("site") or row.get("name") or "")
        if not url and not site:
            continue
        key = (site.casefold(), url)
        if key in seen:
            continue
        seen.add(key)
        findings.append(IdentityFinding(
            identifier_type="username",
            value=username,
            status="possible_profile",
            source="Maigret",
            url=url,
            title=site or urlparse(url).netloc,
            details="Maigret reports a public profile match. Manually verify profile content and ownership.",
            confidence="medium",
        ))
    return findings


def check_username(
    username: str,
    *,
    max_sites: int = 500,
    timeout_per_site: int = 15,
    process_timeout: int = 900,
    executable: str = "maigret",
    proxy_url: str | None = None,
) -> dict[str, Any]:
    """Check a username against Maigret's public site database, without API keys."""
    username = _valid_username(username)
    if not 1 <= int(max_sites) <= 3000:
        raise ValueError("max_sites must be between 1 and 3000.")
    if not 5 <= int(timeout_per_site) <= 60:
        raise ValueError("timeout_per_site must be between 5 and 60 seconds.")
    from .network import configured_proxy_url, validate_proxy_url
    selected_proxy = validate_proxy_url(configured_proxy_url() if proxy_url is None else proxy_url)
    binary = shutil.which(executable)
    if not binary:
        return {
            "status": "tool_missing",
            "username": username,
            "tool": "Maigret",
            "install_hint": "Install with: python -m pip install maigret",
            "checked_sites": 0,
            "findings": [],
        }

    with tempfile.TemporaryDirectory(prefix="smartintel-maigret-") as tmp:
        output_dir = Path(tmp) / "reports"
        output_dir.mkdir()
        command = [
            binary, username,
            "--json", "simple",
            "--folderoutput", str(output_dir),
            "--top-sites", str(int(max_sites)),
            "--timeout", str(int(timeout_per_site)),
            "--retries", "1",
            "--max-connections", "25",
            "--no-recursion",
            "--no-autoupdate",
        ]
        if selected_proxy:
            command.extend(["--proxy", selected_proxy])
        started = time.monotonic()
        try:
            completed = subprocess.run(
                command, capture_output=True, text=True, timeout=int(process_timeout),
                check=False, shell=False,
            )
        except subprocess.TimeoutExpired:
            return {"status": "timed_out", "username": username, "tool": "Maigret",
                    "checked_sites": 0, "findings": [], "error": "Maigret exceeded the process timeout."}

        files = list(output_dir.rglob("*.json"))
        findings: list[IdentityFinding] = []
        for file in files:
            findings.extend(parse_maigret_report(file, username))
        # Deduplicate across report files.
        unique: dict[tuple[str, str], IdentityFinding] = {}
        for item in findings:
            unique[(item.source, item.url or item.title)] = item

        output = completed.stdout[-4000:] if completed.stdout else ""
        errors = completed.stderr[-2000:] if completed.stderr else ""
        if completed.returncode and not unique:
            status = "tool_error"
        else:
            status = "completed"
        return {
            "status": status,
            "username": username,
            "tool": "Maigret",
            "requested_site_limit": int(max_sites),
            "checked_sites": None,
            "findings": [item.to_dict() for item in unique.values()],
            "duration_seconds": round(time.monotonic() - started, 2),
            "return_code": completed.returncode,
            "stdout_tail": output,
            "stderr_tail": errors,
            "interpretation": "Matches are candidate profiles, not proof of identity. Maigret's database and each site's responses determine actual coverage.",
        }


def inspect_email_domain(email: str, *, dns_timeout: float = 3.0) -> dict[str, Any]:
    """Validate an email address and inspect only its public mail-domain DNS."""
    value = (email or "").strip()
    if len(value) > 254 or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", value):
        raise ValueError("Enter a syntactically valid email address.")
    domain = value.rsplit("@", 1)[1].rstrip(".").lower()
    mx_records: list[str] = []
    dns_status = "not_checked"
    try:
        import dns.resolver  # type: ignore
        resolver = dns.resolver.Resolver()
        resolver.lifetime = dns_timeout
        mx_records = sorted(str(record.exchange).rstrip(".") for record in resolver.resolve(domain, "MX"))
        dns_status = "mx_found" if mx_records else "no_mx"
    except ImportError:
        try:
            socket.getaddrinfo(domain, 25, type=socket.SOCK_STREAM)
            dns_status = "domain_resolves_no_mx_validation"
        except OSError:
            dns_status = "dns_unavailable_or_domain_not_resolving"
    except Exception as exc:
        dns_status = "dns_lookup_failed"
    return {
        "status": "completed",
        "identifier_type": "email",
        "email": value,
        "domain": domain,
        "mail_dns_status": dns_status,
        "mx_records": mx_records,
        "public_search_urls": [
            "https://www.google.com/search?q=" + quote('"' + value + '"'),
            "https://www.bing.com/search?q=" + quote('"' + value + '"'),
            "https://duckduckgo.com/?q=" + quote('"' + value + '"'),
        ],
        "limitations": "DNS only indicates mail-domain configuration; it cannot confirm that this mailbox exists or belongs to a person. No SMTP probing or breach-dump searching is performed.",
    }


def inspect_phone_number(phone: str, *, default_region: str = "MY") -> dict[str, Any]:
    """Normalize a phone number with the optional offline phonenumbers package."""
    value = (phone or "").strip()
    if not value or len(value) > 40 or not re.fullmatch(r"[+0-9().\-\s]+", value):
        raise ValueError("Enter a phone number using digits and common separators.")
    try:
        import phonenumbers  # type: ignore
        parsed = phonenumbers.parse(value, default_region)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)
        normalized = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        region = phonenumbers.region_code_for_number(parsed)
        number_type = phonenumbers.number_type(parsed)
        type_name = {
            phonenumbers.PhoneNumberType.MOBILE: "mobile",
            phonenumbers.PhoneNumberType.FIXED_LINE: "fixed_line",
            phonenumbers.PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_line_or_mobile",
            phonenumbers.PhoneNumberType.VOIP: "voip",
        }.get(number_type, "other_or_unknown")
        return {
            "status": "completed", "identifier_type": "phone",
            "input": value, "e164": normalized, "valid_numbering_plan": valid,
            "possible_number": possible, "region": region, "number_type": type_name,
            "public_search_urls": [
                "https://www.google.com/search?q=" + quote('"' + normalized + '"'),
                "https://www.bing.com/search?q=" + quote('"' + normalized + '"'),
                "https://duckduckgo.com/?q=" + quote('"' + normalized + '"'),
            ],
            "limitations": "Numbering-plan validity does not establish assignment, subscriber identity, current ownership, or reachability. Carrier/owner lookups are not inferred.",
        }
    except ImportError:
        digits = re.sub(r"\D", "", value)
        return {
            "status": "dependency_missing", "identifier_type": "phone", "input": value,
            "digits": digits, "install_hint": "Install optional offline parser: python -m pip install phonenumbers",
            "limitations": "Basic digit normalization only; install phonenumbers for numbering-plan validation.",
        }


def extract_profile_metadata(html: str, page_url: str) -> dict[str, Any]:
    """Extract conservative public profile metadata; never infer account ownership."""
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html or "", "html.parser")
    def meta(*names: str) -> str:
        for name in names:
            tag = soup.find("meta", attrs={"property": name}) or soup.find("meta", attrs={"name": name})
            if tag and tag.get("content"):
                return str(tag["content"]).strip()[:1000]
        return ""
    canonical = soup.find("link", rel="canonical")
    same_as: list[str] = []
    for link in soup.find_all("a", href=True):
        rel = link.get("rel") or []
        if isinstance(rel, str):
            rel = [rel]
        if "me" in rel:
            href = str(link["href"])
            if href.startswith(("https://", "http://")):
                same_as.append(href)
    return {
        "url": page_url,
        "title": (soup.title.get_text(" ", strip=True)[:300] if soup.title else ""),
        "description": meta("og:description", "description", "twitter:description"),
        "display_name": meta("og:title", "twitter:title"),
        "canonical_url": str(canonical.get("href", "")) if canonical else "",
        "rel_me_links": list(dict.fromkeys(same_as))[:30],
        "interpretation": "Public page metadata only. rel=me links are self-asserted links and require manual validation.",
    }


class PivotQueue:
    """Evidence-linked, analyst-approved username pivot queue.

    Proposals never execute automatically. The analyst must approve each
    identifier before a caller submits it to another collection run.
    """
    def __init__(self, *, max_depth: int = 2, max_targets: int = 25):
        if not 0 <= max_depth <= 5 or not 1 <= max_targets <= 100:
            raise ValueError("Pivot limits must be max_depth 0-5 and max_targets 1-100.")
        self.max_depth = max_depth
        self.max_targets = max_targets
        self._items: dict[str, dict[str, Any]] = {}

    def propose(self, username: str, *, source_url: str, reason: str, depth: int) -> dict[str, Any]:
        candidate = _valid_username(username)
        if depth < 1 or depth > self.max_depth:
            raise ValueError("Pivot depth is outside the configured limit.")
        if not source_url.startswith(("https://", "http://")):
            raise ValueError("Every pivot must include an HTTP(S) evidence URL.")
        if candidate in self._items:
            return dict(self._items[candidate])
        if len(self._items) >= self.max_targets:
            raise ValueError("Pivot target limit reached.")
        item = {
            "username": candidate, "source_url": source_url, "reason": reason[:500],
            "depth": depth, "status": "pending_analyst_approval",
        }
        self._items[candidate] = item
        return dict(item)

    def approve(self, username: str) -> dict[str, Any]:
        candidate = _valid_username(username)
        if candidate not in self._items:
            raise KeyError("No such pivot proposal.")
        self._items[candidate]["status"] = "approved"
        return dict(self._items[candidate])

    def list(self) -> list[dict[str, Any]]:
        return [dict(item) for item in self._items.values()]


def check_identity(identifier_type: str, value: str, **options: Any) -> dict[str, Any]:
    """Dispatch a no-paid-API identity check by explicit identifier type."""
    kind = (identifier_type or "").strip().lower()
    if kind == "username":
        return check_username(value, **options)
    if kind == "email":
        return inspect_email_domain(value, **options)
    if kind == "phone":
        return inspect_phone_number(value, **options)
    if kind == "profile_url":
        return fetch_public_profile_metadata(value, **options)
    raise ValueError("identifier_type must be username, email, phone or profile_url")


def _public_profile_url(url: str) -> str:
    """Reject non-public hosts before making a passive profile-page request."""
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Profile URL must be an absolute HTTP(S) URL.")
    if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
        raise ValueError("Profile URL must not contain credentials or a non-standard port.")
    host = parsed.hostname.rstrip(".")
    try:
        address = __import__("ipaddress").ip_address(host)
        addresses = [address]
    except ValueError:
        try:
            addresses = [__import__("ipaddress").ip_address(item[4][0])
                         for item in socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80),
                                                        type=socket.SOCK_STREAM)]
        except OSError as exc:
            raise ValueError("Profile host could not be resolved.") from exc
    if not addresses or any(not address.is_global for address in addresses):
        raise ValueError("Only publicly routable profile hosts are allowed.")
    return url.strip()


def fetch_public_profile_metadata(url: str, *, timeout: float = 10.0, max_bytes: int = 2_000_000) -> dict[str, Any]:
    """Fetch one public HTML profile page without cookies, redirects or challenge bypass."""
    safe_url = _public_profile_url(url)
    from .collectors.passive import _get_public_pinned
    response = _get_public_pinned(safe_url)
    if response.is_redirect or response.is_permanent_redirect:
        return {"status": "redirect_not_followed", "url": safe_url,
                "limitations": "Redirects are not followed automatically; review the destination manually."}
    response.raise_for_status()
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type:
        return {"status": "not_html", "url": safe_url, "content_type": content_type}
    if len(response.content) > max_bytes:
        raise ValueError("Profile page exceeds the 2 MB parsing limit.")
    html = response.content.decode(response.encoding or "utf-8", errors="replace")

    metadata = extract_profile_metadata(html, safe_url)
    candidates: list[dict[str, str]] = []
    for linked_url in metadata["rel_me_links"]:
        parsed = urlparse(linked_url)
        parts = [part for part in parsed.path.split("/") if part]
        if not parts:
            continue
        handle = parts[-1].lstrip("@")
        try:
            handle = _valid_username(handle)
        except ValueError:
            continue
        candidates.append({
            "username": handle,
            "url": linked_url,
            "reason": "Public profile contains a self-asserted rel=me link; verify before pivoting.",
            "status": "pending_analyst_approval",
        })
    unique = {item["username"]: item for item in candidates}
    return {
        "status": "completed",
        "identifier_type": "profile_url",
        "profile": metadata,
        "pivot_candidates": list(unique.values())[:20],
        "limitations": "Only public HTML metadata and rel=me links were parsed. Linked accounts are self-asserted leads, not verified identities. No redirects, logins, cookies, CAPTCHAs or access controls are bypassed.",
    }

