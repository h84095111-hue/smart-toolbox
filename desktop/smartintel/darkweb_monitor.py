"""Single-source Tor onion page checks.

This deliberately does not crawl onion directories, marketplaces, forums,
credential dumps or private services. It fetches one analyst-configured v3
.onion URL over a local Tor SOCKS5H proxy, with no redirects or downloads.
"""
from __future__ import annotations

import hashlib
import html
import ipaddress
import re
import socket
import ssl
import http.client
from urllib.parse import urlparse, unquote


def _local_tor_proxy():
    from .network import configured_proxy_url, validate_proxy_url
    value = validate_proxy_url(configured_proxy_url())
    if not value:
        raise RuntimeError("Dark-web monitoring requires a configured local Tor SOCKS5H proxy.")
    parsed = urlparse(value)
    if parsed.scheme != "socks5h":
        raise RuntimeError("Dark-web monitoring requires socks5h:// so .onion names are resolved by Tor.")
    host = parsed.hostname or ""
    if host.lower() != "localhost":
        try:
            if not ipaddress.ip_address(host).is_loopback:
                raise RuntimeError("For onion monitoring, configure a local Tor SOCKS5H listener on loopback.")
        except ValueError:
            raise RuntimeError("For onion monitoring, configure a local Tor SOCKS5H listener on 127.0.0.1 or localhost.")
    return parsed


def fetch_onion_page(url: str) -> dict:
    parsed = urlparse((url or "").strip())
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or not parsed.hostname.endswith(".onion"):
        raise ValueError("Enter one exact HTTP(S) v3 .onion URL.")
    onion_host = parsed.hostname[:-6]
    if not re.fullmatch(r"[a-z2-7]{56}", onion_host):
        raise ValueError("Only modern v3 .onion hostnames (56 base32 characters) are supported.")
    if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
        raise ValueError("Onion monitoring rejects embedded credentials and non-standard ports.")
    proxy = _local_tor_proxy()
    try:
        import socks
    except ImportError as exc:
        raise RuntimeError("Tor SOCKS routing requires PySocks. Install desktop requirements and restart.") from exc
    proxy_port = proxy.port or 9050
    sock = socks.socksocket()
    sock.set_proxy(socks.SOCKS5, proxy.hostname, proxy_port,
                   rdns=True, username=unquote(proxy.username or "") or None,
                   password=unquote(proxy.password or "") or None)
    sock.settimeout(25)
    target_port = parsed.port or (443 if parsed.scheme == "https" else 80)
    connection = http.client.HTTPConnection(parsed.hostname, target_port, timeout=25)
    try:
        sock.connect((parsed.hostname, target_port))
        if parsed.scheme == "https":
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=parsed.hostname)
        connection.sock = sock
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        connection.putrequest("GET", path, skip_accept_encoding=True)
        connection.putheader("Host", parsed.hostname)
        connection.putheader("User-Agent", "SmartIntel/2.1 public research client")
        connection.putheader("Accept", "text/html,text/plain,application/xhtml+xml")
        connection.putheader("Connection", "close")
        connection.endheaders()
        response = connection.getresponse()
        if 300 <= response.status < 400:
            raise RuntimeError("Onion redirects are blocked. Add the final .onion URL as a separate source.")
        if response.status != 200:
            raise RuntimeError("Onion page returned HTTP " + str(response.status) + ".")
        content_type = response.getheader("Content-Type", "").casefold()
        if not any(value in content_type for value in ("text/html", "text/plain", "application/xhtml+xml")):
            raise RuntimeError("Only HTML or plain-text onion pages are supported; file downloads are disabled.")
        payload = response.read(500_001)
        if len(payload) > 500_000:
            raise ValueError("Onion page exceeds the 500 KiB inspection limit.")
        encoding = response.headers.get_content_charset() or "utf-8"
        text = payload.decode(encoding, errors="replace")
        try:
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(text, "html.parser")
            title = soup.title.get_text(" ", strip=True) if soup.title else parsed.hostname
            body = soup.get_text(" ", strip=True)
        except Exception:
            title = parsed.hostname
            body = re.sub(r"<[^>]*>", " ", text)
        body = html.unescape(body)[:16000]
        digest = hashlib.sha256(payload).hexdigest()
        return {"title": title[:240], "text": body, "sha256": digest,
                "url": parsed.geturl(), "size_bytes": len(payload),
                "transport": "Tor SOCKS5H via configured local proxy"}
    finally:
        connection.close()
        try:
            sock.close()
        except Exception:
            pass


def monitor_onion_page(url: str, *, keywords: list[str] | None = None) -> list[dict]:
    result = fetch_onion_page(url)
    terms = [str(term).strip().casefold() for term in (keywords or []) if str(term).strip()]
    haystack = (result["title"] + " " + result["text"]).casefold()
    if terms and not any(term in haystack for term in terms):
        return []
    item_id = hashlib.sha256((result["url"] + "|" + result["sha256"]).encode()).hexdigest()
    return [{
        "item_id": item_id, "source": "Tor .onion public page",
        "title": result["title"], "text": result["text"], "url": result["url"],
        "published_at": "", "author": "", "sha256": result["sha256"],
    }]


def run_content_monitor(kind: str, config: dict) -> dict:
    from .social_monitor import run_social_monitor
    if kind in {"mastodon_account", "bluesky_search", "rss_feed"}:
        items = run_social_monitor(kind, config)
        return {"items": items, "config": config,
                "status": str(len(items)) + " matching public posts/feed entries"}
    if kind == "telegram_channels":
        from .telegram_monitor import poll_telegram_channels
        return poll_telegram_channels(config)
    if kind == "onion_page":
        items = monitor_onion_page(config.get("url", ""), keywords=config.get("keywords", []))
        return {"items": items, "config": config,
                "status": str(len(items)) + " matching public onion page snapshot(s)"}
    raise ValueError("Unsupported content-monitor type.")
