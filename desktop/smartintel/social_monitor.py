"""Read-only social-media and public-feed monitoring.

Only public posts and public RSS/Atom items are collected. Requests use the
existing pinned-public-fetch guard: public IPs only, no redirects, no private
or loopback destinations.
"""
from __future__ import annotations

import hashlib
import re
from urllib.parse import quote, urlparse, urlencode, parse_qsl
from defusedxml import ElementTree as ET
from defusedxml.common import DefusedXmlException



_SENSITIVE_QUERY_KEYS = {
    "access_token", "auth", "authorization", "api_key", "apikey", "key",
    "password", "passwd", "secret", "session", "signature", "token",
}


def _reject_secret_query(parsed) -> None:
    for key, _value in parse_qsl(parsed.query, keep_blank_values=True):
        lowered = key.casefold()
        if lowered in _SENSITIVE_QUERY_KEYS or lowered.endswith("_token") or lowered.endswith("_secret"):
            raise ValueError("Public monitor URLs must not embed authentication tokens, API keys or session secrets.")


def _fetch_json(url: str) -> dict | list:
    from .collectors.passive import _get_public_pinned
    parsed = urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Social media API requests must use public HTTPS URLs.")
    response = _get_public_pinned(url)
    if len(response.content) > 1_500_000:
        raise ValueError("Social API response exceeds the 1.5 MiB limit.")
    return response.json()


def _clean_html(value: str) -> str:
    try:
        from bs4 import BeautifulSoup
        return BeautifulSoup(value or "", "html.parser").get_text(" ", strip=True)[:12000]
    except Exception:
        return re.sub(r"<[^>]*>", " ", value or "")[:12000]


def _item(source: str, item_id: str, title: str, text: str, url: str,
          published: str = "", author: str = "") -> dict:
    key = hashlib.sha256((source + "|" + item_id).encode("utf-8", errors="replace")).hexdigest()
    return {
        "item_id": key, "source": source, "title": (title or "Public post")[:240],
        "text": (text or "")[:12000], "url": (url or "")[:2000],
        "published_at": (published or "")[:80], "author": (author or "")[:240],
    }


def _matches_keywords(item: dict, keywords: list[str]) -> bool:
    terms = [str(term).strip().casefold() for term in keywords if str(term).strip()]
    if not terms:
        return True
    haystack = (item.get("title", "") + " " + item.get("text", "") + " " +
                item.get("author", "")).casefold()
    return any(term in haystack for term in terms)


def monitor_mastodon_account(account: str, *, keywords: list[str] | None = None,
                             limit: int = 40) -> list[dict]:
    """Fetch only public posts from one explicitly supplied Mastodon account."""
    raw = (account or "").strip()
    if not raw:
        raise ValueError("Enter a Mastodon account handle or public profile URL.")
    parsed = urlparse(raw if "://" in raw else "")
    if parsed.scheme:
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("Mastodon profile URLs must be public HTTPS URLs.")
        _reject_secret_query(parsed)
        host = parsed.hostname
        match = re.search(r"/@([A-Za-z0-9_.-]+)", parsed.path)
        if not match:
            raise ValueError("Could not read the account handle from the Mastodon profile URL.")
        acct = match.group(1)
    else:
        value = raw.lstrip("@")
        if "@" not in value:
            raise ValueError("Use @account@instance or a public Mastodon profile URL.")
        acct, host = value.split("@", 1)
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", acct) or not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host):
        raise ValueError("Mastodon account handle or instance name is invalid.")
    base = "https://" + host.lower()
    lookup = _fetch_json(base + "/api/v1/accounts/lookup?" +
                         urlencode({"acct": acct}))
    if not isinstance(lookup, dict) or not lookup.get("id"):
        raise RuntimeError("Mastodon did not return the requested public account.")
    statuses = _fetch_json(base + "/api/v1/accounts/" + quote(str(lookup["id"]), safe="") +
                            "/statuses?" + urlencode({
                                "limit": max(1, min(int(limit), 40)),
                                "exclude_reblogs": "true",
                                "exclude_replies": "false",
                            }))
    if not isinstance(statuses, list):
        raise RuntimeError("Mastodon returned an unexpected statuses response.")
    name = str(lookup.get("display_name") or lookup.get("acct") or acct)
    results = []
    for post in statuses:
        if not isinstance(post, dict) or post.get("visibility") != "public":
            continue
        text = _clean_html(str(post.get("content", "")))
        item = _item("Mastodon", str(post.get("id", "")),
                     name + ": " + (text[:160] or "Public post"),
                     text, str(post.get("url", "")),
                     str(post.get("created_at", "")), str(post.get("account", {}).get("acct", name)))
        if item["item_id"] and _matches_keywords(item, keywords or []):
            results.append(item)
    return results


def monitor_bluesky_search(query: str, *, keywords: list[str] | None = None,
                           limit: int = 30) -> list[dict]:
    """Search public Bluesky posts using the public AppView endpoint."""
    value = (query or "").strip()
    if len(value) < 2 or len(value) > 200:
        raise ValueError("Bluesky search terms must be 2-200 characters.")
    endpoint = "https://public.api.bsky.app/xrpc/app.bsky.feed.searchPosts?" + urlencode({
        "q": value, "limit": max(1, min(int(limit), 30)),
    })
    payload = _fetch_json(endpoint)
    posts = payload.get("posts", []) if isinstance(payload, dict) else []
    results = []
    for post in posts:
        if not isinstance(post, dict):
            continue
        record = post.get("record") if isinstance(post.get("record"), dict) else {}
        author = post.get("author") if isinstance(post.get("author"), dict) else {}
        text = str(record.get("text", ""))[:12000]
        handle = str(author.get("handle", ""))
        uri = str(post.get("uri", ""))
        rkey = uri.rsplit("/", 1)[-1]
        url = "https://bsky.app/profile/" + quote(handle, safe="") + "/post/" + quote(rkey, safe="")
        item = _item("Bluesky", uri, (handle or "Bluesky") + ": " + (text[:160] or "Public post"),
                     text, url, str(record.get("createdAt", "")),
                     str(author.get("displayName") or handle))
        if uri and _matches_keywords(item, keywords or []):
            results.append(item)
    return results


def monitor_rss_feed(feed_url: str, *, keywords: list[str] | None = None,
                     limit: int = 60) -> list[dict]:
    """Read a user-specified public RSS/Atom feed; no link crawling."""
    parsed = urlparse((feed_url or "").strip())
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.port not in {None, 443}):
        raise ValueError("RSS/Atom monitoring requires a public HTTPS feed URL.")
    _reject_secret_query(parsed)
    from .collectors.passive import _get_public_pinned
    response = _get_public_pinned(parsed.geturl())
    if len(response.content) > 1_500_000:
        raise ValueError("Feed exceeds the 1.5 MiB limit.")
    try:
        root = ET.fromstring(response.content)
    except (ET.ParseError, DefusedXmlException) as exc:
        raise ValueError("The configured URL did not return valid RSS/Atom XML.") from exc
    entries = []
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1].lower()
        if tag in {"item", "entry"}:
            entries.append(element)
    results = []
    for entry in entries[:max(1, min(int(limit), 60))]:
        values = {}
        links = []
        for child in list(entry):
            tag = child.tag.rsplit("}", 1)[-1].lower()
            if tag == "link":
                link = child.attrib.get("href") or (child.text or "").strip()
                if link:
                    links.append(link)
            else:
                values[tag] = (child.text or "").strip()
        title = _clean_html(values.get("title", "Public feed item"))
        description = _clean_html(values.get("description") or values.get("summary") or
                                  values.get("encoded") or values.get("content", ""))
        item_url = links[0] if links else values.get("guid", "")
        stable_id = values.get("id") or values.get("guid") or item_url or title
        item = _item("RSS/Atom public feed", stable_id, title, description,
                     item_url, values.get("published") or values.get("pubdate") or
                     values.get("updated", ""))
        if _matches_keywords(item, keywords or []):
            results.append(item)
    return results


def run_social_monitor(kind: str, config: dict) -> list[dict]:
    keywords = config.get("keywords", [])
    if kind == "mastodon_account":
        return monitor_mastodon_account(config.get("account", ""), keywords=keywords)
    if kind == "bluesky_search":
        return monitor_bluesky_search(config.get("query", ""), keywords=keywords)
    if kind == "rss_feed":
        return monitor_rss_feed(config.get("feed_url", ""), keywords=keywords)
    raise ValueError("Unsupported public social/feed monitor type.")
