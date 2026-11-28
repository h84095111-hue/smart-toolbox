"""Telegram public-channel monitoring via the official Bot API.

The bot receives only updates Telegram makes available to that bot. The bot
must be added to each public channel. getUpdates is incremental (not history);
Telegram retains pending updates for at most 24 hours.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import re
import requests

from .providers.ai import get_api_key
from .network import requests_proxy_map


def normalize_public_channels(value) -> list[str]:
    if isinstance(value, str):
        values = value.split(",")
    else:
        values = list(value or [])
    channels = []
    for raw in values:
        channel = str(raw).strip()
        if not channel:
            continue
        channel = channel.removeprefix("https://t.me/").removeprefix("http://t.me/").lstrip("@").rstrip("/")
        if not re.fullmatch(r"[A-Za-z0-9_]{5,64}", channel):
            raise ValueError("Telegram monitoring accepts public channel usernames only (for example @example_channel).")
        normalized = "@" + channel.casefold()
        if normalized not in channels:
            channels.append(normalized)
    if not channels:
        raise ValueError("Enter at least one public Telegram channel username.")
    if len(channels) > 50:
        raise ValueError("A Telegram monitor can watch at most 50 public channels.")
    return channels


def poll_telegram_channels(config: dict) -> dict:
    token = (get_api_key("telegram_bot_token") or "").strip()
    if not re.fullmatch(r"\d{5,15}:[A-Za-z0-9_-]{20,}", token):
        raise RuntimeError("Configure a valid Telegram Bot API token in Smart Intel settings.")
    channels = set(normalize_public_channels(config.get("channels", [])))
    try:
        offset = int(config.get("offset", 0))
    except (TypeError, ValueError):
        offset = 0
    params = {"limit": 100, "timeout": 0,
              "allowed_updates": '["channel_post","edited_channel_post"]'}
    if offset > 0:
        params["offset"] = offset
    endpoint = "https://api.telegram.org/bot" + token + "/getUpdates"
    try:
        response = requests.get(endpoint, params=params, headers={
            "User-Agent": "SmartIntel/2.1 public channel monitor",
        }, timeout=20, proxies=requests_proxy_map(), allow_redirects=False)
    except requests.RequestException:
        # Do not echo the Bot API URL: it contains the secret token.
        raise RuntimeError("Could not reach the Telegram Bot API through the configured network route.") from None
    if response.status_code != 200:
        raise RuntimeError("Telegram Bot API request failed with HTTP " + str(response.status_code) + ".")
    payload = response.json()
    if not payload.get("ok"):
        error = str(payload.get("description", "Telegram returned an API error."))[:220]
        raise RuntimeError("Telegram Bot API: " + error)
    updates = payload.get("result", [])
    if not isinstance(updates, list):
        raise RuntimeError("Telegram returned an invalid updates list.")
    next_offset = max([offset] + [int(row.get("update_id", 0)) + 1 for row in updates])
    results = []
    for update in updates:
        message = update.get("channel_post") or update.get("edited_channel_post")
        if not isinstance(message, dict):
            continue
        chat = message.get("chat", {})
        username = str(chat.get("username", "")).casefold()
        if not username or ("@" + username) not in channels:
            continue
        text = str(message.get("text") or message.get("caption") or "").strip()
        if not text:
            continue
        message_id = str(message.get("message_id", ""))
        channel_id = str(chat.get("id", ""))
        stable = channel_id + ":" + message_id + ":" + str(message.get("edit_date", update.get("update_id", "")))
        published = ""
        try:
            published = datetime.fromtimestamp(int(message.get("date", 0)), tz=timezone.utc).isoformat()
        except (TypeError, ValueError, OSError):
            pass
        url = "https://t.me/" + username + "/" + message_id
        item_key = hashlib.sha256(("Telegram|" + stable).encode("utf-8")).hexdigest()
        results.append({
            "item_id": item_key, "source": "Telegram public channel",
            "title": "@" + username + ": " + text[:160],
            "text": text[:12000], "url": url, "published_at": published,
            "author": "@" + username,
        })
    return {"items": results, "config": {**config, "channels": sorted(channels),
                                         "offset": next_offset},
            "status": "received " + str(len(updates)) + " updates; " + str(len(results)) +
                      " matching public channel posts"}


