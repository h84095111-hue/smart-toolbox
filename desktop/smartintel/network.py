"""Explicit egress routing with pinned-target support.

Proxy routing is opt-in. This module does not start Tor or manage an OS VPN.
Public destinations are resolved and validated by the caller before a socket is
opened; SOCKS connections receive the already-validated IP, not a hostname.
"""
from __future__ import annotations

import base64
import os
import socket
import ssl
from urllib.parse import urlsplit, unquote


def configured_proxy_url() -> str:
    value = os.getenv("SMART_INTEL_PROXY_URL", "").strip()
    if not value:
        try:
            from .providers.ai import get_api_key
            value = (get_api_key("network_proxy") or "").strip()
        except Exception:
            value = ""
    return value


def validate_proxy_url(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    parsed = urlsplit(value)
    if parsed.scheme.lower() not in {"http", "https", "socks5", "socks5h"}:
        raise ValueError("Proxy must use http://, https://, socks5:// or socks5h://.")
    if not parsed.hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
        raise ValueError("Proxy URL must contain only a host, optional port and optional credentials.")
    if parsed.port is not None and not (1 <= parsed.port <= 65535):
        raise ValueError("Proxy port is invalid.")
    return value


def proxy_label(value: str | None = None) -> str:
    value = validate_proxy_url(configured_proxy_url() if value is None else value)
    if not value:
        return "Direct / OS network route"
    parsed = urlsplit(value)
    scheme = "Tor SOCKS5" if parsed.scheme.startswith("socks5") else "HTTP proxy"
    return f"{scheme} at {parsed.hostname}:{parsed.port or (443 if parsed.scheme == 'https' else 1080 if parsed.scheme.startswith('socks5') else 8080)}"


def requests_proxy_map() -> dict[str, str] | None:
    value = validate_proxy_url(configured_proxy_url())
    if not value:
        return None
    return {"http": value, "https": value}


def _proxy_address(parsed):
    port = parsed.port or (443 if parsed.scheme == "https" else 1080 if parsed.scheme.startswith("socks5") else 8080)
    return parsed.hostname, port


def open_pinned_socket(target_ip: str, target_port: int, *, server_hostname: str,
                       timeout: float = 12.0, proxy_url: str | None = None,
                       use_tls: bool = True):
    """Open a socket to a previously validated public IP through the chosen route."""
    import ipaddress
    address = ipaddress.ip_address(target_ip)
    if not address.is_global:
        raise ValueError("Only globally routable destination IP addresses are allowed.")
    route = validate_proxy_url(configured_proxy_url() if proxy_url is None else proxy_url)
    sock = None
    if not route:
        sock = socket.create_connection((str(address), int(target_port)), timeout=timeout)
    else:
        parsed = urlsplit(route)
        proxy_host, proxy_port = _proxy_address(parsed)
        username = unquote(parsed.username or "")
        password = unquote(parsed.password or "")
        if parsed.scheme.startswith("socks5"):
            try:
                import socks
            except ImportError as exc:
                raise RuntimeError("SOCKS5 routing requires PySocks. Install PySocks and restart Smart Intel.") from exc
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, proxy_host, proxy_port,
                           rdns=False, username=username or None, password=password or None)
            sock.settimeout(timeout)
            sock.connect((str(address), int(target_port)))
        else:
            sock = socket.create_connection((proxy_host, proxy_port), timeout=timeout)
            destination = f"[{address}]:{target_port}" if address.version == 6 else f"{address}:{target_port}"
            auth = ""
            if parsed.username is not None:
                token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
                auth = f"Proxy-Authorization: Basic {token}\r\n"
            request = (f"CONNECT {destination} HTTP/1.1\r\n"
                       f"Host: {destination}\r\n{auth}Proxy-Connection: Keep-Alive\r\n\r\n")
            sock.sendall(request.encode("ascii"))
            stream = sock.makefile("rb")
            status = stream.readline(8192).decode("iso-8859-1", errors="replace").strip()
            while True:
                line = stream.readline(8192)
                if not line or line in (b"\r\n", b"\n"):
                    break
            stream.close()
            if " 200 " not in f" {status} ":
                raise ConnectionError(f"HTTP proxy CONNECT failed: {status[:160]}")
    if use_tls:
        context = ssl.create_default_context()
        sock = context.wrap_socket(sock, server_hostname=server_hostname)
    return sock
