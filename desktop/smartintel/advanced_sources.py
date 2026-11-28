"""Configurable public corporate, court-opinion and sanctions data connectors.

Provider keys remain in the OS credential store. Search results are candidate
records for analyst review, never legal, identity or sanctions determinations.
"""
from __future__ import annotations

from urllib.parse import quote
import requests

from .providers.ai import get_api_key
from .network import requests_proxy_map

UA = {"User-Agent": "SmartIntel/2.1 (public-record research client)"}


def _finding(title, data, source, url, confidence="Low"):
    import json
    return {"title": title, "content": json.dumps(data, indent=2, ensure_ascii=False, default=str),
            "source": source, "url": url, "confidence": confidence,
            "kind": "Public-record candidate"}


def _get(url, *, params=None, headers=None, timeout=18):
    response = requests.get(url, params=params, headers={**UA, **(headers or {})},
                            timeout=timeout, proxies=requests_proxy_map(), allow_redirects=False)
    response.raise_for_status()
    return response


def opencorporates_search(query: str) -> dict:
    value = (query or "").strip()
    if len(value) < 2 or len(value) > 160:
        raise ValueError("Enter a company name between 2 and 160 characters.")
    key = get_api_key("opencorporates")
    if not key:
        raise RuntimeError("Configure an OpenCorporates API token in Smart Intel settings.")
    url = "https://api.opencorporates.com/v0.4/companies/search"
    payload = _get(url, params={"q": value, "per_page": 20},
                   headers={"X-API-TOKEN": key}).json()
    rows = payload.get("results", {}).get("companies", [])
    companies = []
    for row in rows[:20]:
        company = row.get("company", row)
        companies.append({k: company.get(k) for k in (
            "name", "company_number", "jurisdiction_code", "company_type",
            "current_status", "incorporation_date", "dissolution_date",
            "registry_url", "opencorporates_url", "registered_address"
        ) if k in company})
    return _finding("OpenCorporates company search", {"query": value, "results": companies,
        "note": "Match company number and jurisdiction with the official registry before attribution."},
        "OpenCorporates API", url)


def courtlistener_search(query: str) -> dict:
    value = (query or "").strip()
    if len(value) < 2 or len(value) > 240:
        raise ValueError("Enter a court-opinion search phrase between 2 and 240 characters.")
    token = get_api_key("courtlistener")
    headers = {"Authorization": "Token " + token} if token else {}
    url = "https://www.courtlistener.com/api/rest/v4/search/"
    payload = _get(url, params={"q": value, "type": "o", "order_by": "dateFiled desc"},
                   headers=headers).json()
    rows = payload.get("results", [])
    opinions = []
    for row in rows[:30]:
        opinions.append({k: row.get(k) for k in (
            "caseName", "court", "dateFiled", "dateArgued", "docketNumber",
            "citation", "absolute_url", "snippet"
        ) if k in row})
    return _finding("CourtListener published-opinion search",
        {"query": value, "count": payload.get("count"), "results": opinions,
         "note": "Search covers published opinion records. It is not a complete docket/court-record search; review jurisdiction and the original opinion."},
        "CourtListener API", url)


def opensanctions_search(query: str, *, dataset: str = "sanctions", schema: str = "Person") -> dict:
    """Screen an analyst-supplied name using OpenSanctions query-by-example matching.

    A name-only query is inherently ambiguous. The score ranks candidates and
    is not a final sanctions determination; the analyst must compare primary
    identifiers and source records before any decision.
    """
    value = (query or "").strip()
    if len(value) < 2 or len(value) > 160:
        raise ValueError("Enter a name between 2 and 160 characters.")
    if dataset not in {"sanctions", "peps", "default"}:
        raise ValueError("Unsupported OpenSanctions matching dataset.")
    if schema not in {"Person", "LegalEntity", "Company", "Organization", "Vessel"}:
        raise ValueError("Unsupported entity schema.")
    key = get_api_key("opensanctions")
    if not key:
        raise RuntimeError("Configure an OpenSanctions API key in Smart Intel settings.")
    url = "https://api.opensanctions.org/match/" + dataset
    request_body = {
        "queries": {
            "smartintel-query": {
                "schema": schema,
                "properties": {"name": [value]},
            }
        }
    }
    params = {"limit": 20, "algorithm": "best"}
    if dataset == "sanctions":
        params["topics"] = ["sanction", "sanction.linked", "debarment"]
    elif dataset == "peps":
        params["topics"] = ["role.pep", "role.rca"]
    response = requests.post(
        url, json=request_body, params=params,
        headers={**UA, "Authorization": "ApiKey " + key},
        timeout=22, proxies=requests_proxy_map(), allow_redirects=False,
    )
    response.raise_for_status()
    payload = response.json()
    query_result = payload.get("responses", {}).get("smartintel-query", {})
    rows = query_result.get("results", [])
    matches = []
    for row in rows[:20]:
        matches.append({k: row.get(k) for k in (
            "id", "caption", "schema", "score", "datasets", "properties", "referents"
        ) if k in row})
    return _finding("OpenSanctions candidate screening",
        {"query": value, "dataset": dataset, "schema": schema,
         "query_status": query_result.get("status"),
         "candidate_count": query_result.get("total", len(matches)),
         "results": matches,
         "warning": "A name-only match may produce false positives, especially for common names. Compare date of birth, nationality, identifiers, jurisdiction, designation authority and primary sources. Do not take adverse action from this result alone."},
        "OpenSanctions Matching API", url, "Low")
