"""Have I Been Pwned v3 integration.

Only checks a single email address supplied by an analyst. It never downloads
passwords, stealer logs, credential dumps or account authentication material.
A valid subscription API key and an identifiable User-Agent are required.
"""
from __future__ import annotations

import re
import json
from urllib.parse import quote

import requests

from .providers.ai import get_api_key
from .network import requests_proxy_map

BASE = "https://haveibeenpwned.com/api/v3"


def check_email_breaches(email: str, *, timeout: float = 15.0) -> dict:
    value = (email or "").strip()
    if len(value) > 254 or not re.fullmatch(r"[^\s@<>]+@[^\s@<>]+\.[^\s@<>]+", value):
        raise ValueError("Enter one syntactically valid email address.")
    key = get_api_key("hibp")
    if not key:
        raise RuntimeError("Configure a Have I Been Pwned API subscription key in Smart Intel settings.")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", key.strip()):
        raise ValueError("HIBP API key must be a 32-character hexadecimal subscription key.")
    endpoint = BASE + "/breachedaccount/" + quote(value, safe="")
    response = requests.get(
        endpoint,
        headers={"hibp-api-key": key.strip(), "user-agent": "SmartIntel/2.1 (analyst-authorized email breach notification)"},
        params={"truncateResponse": "false"},
        timeout=timeout,
        proxies=requests_proxy_map(),
        allow_redirects=False,
    )
    if response.status_code == 404:
        breaches = []
    elif response.status_code == 200:
        payload = response.json()
        breaches = payload if isinstance(payload, list) else []
    elif response.status_code == 401:
        raise RuntimeError("HIBP rejected the API key (401). Check the subscription key.")
    elif response.status_code == 403:
        raise RuntimeError("HIBP denied this endpoint for the current subscription (403).")
    elif response.status_code == 429:
        raise RuntimeError("HIBP rate limit reached (429). Retry after the provider's cooldown.")
    else:
        response.raise_for_status()
        raise RuntimeError(f"Unexpected HIBP response: {response.status_code}")
    safe = []
    for item in breaches[:250]:
        if not isinstance(item, dict):
            continue
        safe.append({
            "name": item.get("Name"),
            "title": item.get("Title"),
            "domain": item.get("Domain"),
            "breach_date": item.get("BreachDate"),
            "added_date": item.get("AddedDate"),
            "modified_date": item.get("ModifiedDate"),
            "pwn_count": item.get("PwnCount"),
            "data_classes": item.get("DataClasses", []),
            "is_verified": item.get("IsVerified"),
            "is_sensitive": item.get("IsSensitive"),
        })
    details = {
        "status": "matches_found" if safe else "no_disclosable_matches",
        "email": value,
        "breach_count": len(safe),
        "breaches": safe,
        "data_attribution": "Data from Have I Been Pwned (https://haveibeenpwned.com/), licensed under CC BY 4.0.",
        "api_endpoint": endpoint,
        "limitations": "This is a breach-notification result, not evidence that a mailbox is currently accessible or that the subject controls it. The API returns breach metadata only; no passwords or stolen credential records are retrieved. Use only for an email address you are authorized to assess.",
    }
    return {
        "title": "Have I Been Pwned breach metadata",
        "content": json.dumps(details, ensure_ascii=False, indent=2),
        "source": "Have I Been Pwned",
        "url": "https://haveibeenpwned.com/",
        "confidence": "Low",
        "kind": "Email breach notification metadata",
        **details,
    }
