"""Bounded automatic screenshot capture for public HTTP(S) pages.

Requires the optional Playwright package and a separately installed Chromium
browser. Every navigation/request is checked for public destinations. Redirects
to private/loopback addresses are blocked. This is not a general-purpose browser.
"""
from __future__ import annotations

from pathlib import Path
from urllib.parse import urlparse


def _validate_public_url(url: str) -> str:
    from .collectors.passive import _resolve_public_addresses
    parsed = urlparse(url if "://" in url else "https://" + url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError("Only public HTTP(S) URLs are supported.")
    if parsed.username or parsed.password or parsed.port not in {None, 80, 443}:
        raise ValueError("Screenshot capture rejects embedded credentials and non-standard ports.")
    _resolve_public_addresses(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80))
    return parsed.geturl()


def capture_public_screenshot(url: str, output_path: str | Path, *, full_page: bool = False,
                              timeout_ms: int = 20000) -> dict:
    try:
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise RuntimeError("Automatic screenshots require Playwright. Install requirements-optional.txt and run: python -m playwright install chromium") from exc
    target = _validate_public_url(url)
    if timeout_ms < 1000 or timeout_ms > 60000:
        raise ValueError("Screenshot timeout must be between 1 and 60 seconds.")
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    proxy = None
    from .network import configured_proxy_url, validate_proxy_url
    proxy_url = validate_proxy_url(configured_proxy_url())
    if proxy_url:
        proxy = {"server": proxy_url}
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(headless=True, proxy=proxy)
        try:
            context = browser.new_context(viewport={"width": 1440, "height": 900},
                                          accept_downloads=False, service_workers="block")
            page = context.new_page()
            page.set_default_navigation_timeout(timeout_ms)
            page.set_default_timeout(timeout_ms)

            def guard(route):
                try:
                    parsed = urlparse(route.request.url)
                    if parsed.scheme not in {"http", "https"}:
                        route.abort()
                        return
                    _validate_public_url(route.request.url)
                    route.continue_()
                except Exception:
                    route.abort()

            page.route("**/*", guard)
            response = page.goto(target, wait_until="domcontentloaded", timeout=timeout_ms)
            if response is None:
                raise RuntimeError("Browser did not receive a top-level document response.")
            page.screenshot(path=str(output), full_page=bool(full_page), animations="disabled",
                            timeout=timeout_ms)
            if output.stat().st_size > 25 * 1024 * 1024:
                output.unlink(missing_ok=True)
                raise ValueError("Screenshot exceeds the 25 MiB evidence limit.")
            return {"url": page.url, "status_code": response.status,
                    "title": page.title(), "path": str(output),
                    "size_bytes": output.stat().st_size,
                    "capture_note": "Rendered public page snapshot. Dynamic content may differ by time, region and browser."}
        finally:
            browser.close()
