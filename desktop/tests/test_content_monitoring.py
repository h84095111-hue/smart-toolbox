import json
from types import SimpleNamespace
import pytest

from smartintel import social_monitor, telegram_monitor, darkweb_monitor
from smartintel.storage import Store


def test_mastodon_monitor_keeps_public_posts_and_matches_keywords(monkeypatch):
    responses = [
        {"id": "account-id", "acct": "researcher@mastodon.social",
         "display_name": "Researcher"},
        [
            {"id": "status-1", "visibility": "public", "created_at": "2026-11-28T00:00:00Z",
             "content": "<p>Public update about climate data</p>",
             "url": "https://mastodon.social/@researcher/1",
             "account": {"acct": "researcher"}},
            {"id": "status-2", "visibility": "private", "content": "<p>private message</p>",
             "url": "", "account": {"acct": "researcher"}},
            {"id": "status-3", "visibility": "public", "content": "<p>Unrelated public post</p>",
             "url": "https://mastodon.social/@researcher/3",
             "account": {"acct": "researcher"}},
        ],
    ]
    monkeypatch.setattr(social_monitor, "_fetch_json", lambda url: responses.pop(0))
    result = social_monitor.monitor_mastodon_account(
        "https://mastodon.social/@researcher", keywords=["climate"])
    assert len(result) == 1
    assert result[0]["source"] == "Mastodon"
    assert "climate" in result[0]["text"]
    assert result[0]["url"].endswith("/1")


def test_bluesky_search_public_posts(monkeypatch):
    monkeypatch.setattr(social_monitor, "_fetch_json", lambda url: {
        "posts": [{
            "uri": "at://did:plc:example/app.bsky.feed.post/postkey",
            "record": {"text": "Public post about disaster response", "createdAt": "2026-11-27T00:00:00Z"},
            "author": {"handle": "example.bsky.social", "displayName": "Example"},
        }]
    })
    result = social_monitor.monitor_bluesky_search("disaster response")
    assert len(result) == 1
    assert result[0]["url"] == "https://bsky.app/profile/example.bsky.social/post/postkey"


def test_rss_monitor_parses_atom_and_applies_keywords(monkeypatch):
    xml = b"""<?xml version='1.0' encoding='utf-8'?>
    <feed xmlns='http://www.w3.org/2005/Atom'>
      <entry><id>tag:example,1</id><title>Community safety update</title>
      <link href='https://example.org/posts/1'/><summary>Public notice</summary>
      <updated>2026-11-28T10:00:00Z</updated></entry>
      <entry><id>tag:example,2</id><title>Sports update</title>
      <link href='https://example.org/posts/2'/><summary>Game results</summary></entry>
    </feed>"""
    monkeypatch.setattr("smartintel.collectors.passive._get_public_pinned",
                        lambda url: SimpleNamespace(content=xml))
    result = social_monitor.monitor_rss_feed("https://example.org/feed.xml", keywords=["safety"])
    assert len(result) == 1
    assert result[0]["url"] == "https://example.org/posts/1"


def test_telegram_bot_api_polls_only_configured_public_channels(monkeypatch):
    captured = {}
    class Response:
        status_code = 200
        def json(self):
            return {"ok": True, "result": [
                {"update_id": 120, "channel_post": {
                    "message_id": 9, "date": 1795824000,
                    "chat": {"id": -100123, "username": "public_news"},
                    "text": "A new public channel update",
                }},
                {"update_id": 121, "channel_post": {
                    "message_id": 11, "date": 1795824000,
                    "chat": {"id": -100999, "username": "other_channel"},
                    "text": "Not selected",
                }},
            ]}
    def fake_get(url, **kwargs):
        captured["url"] = url
        captured.update(kwargs)
        return Response()
    monkeypatch.setattr(telegram_monitor, "get_api_key", lambda provider: "123456:abcdefghijklmnopqrstuvwxyz_ABCDE")
    monkeypatch.setattr(telegram_monitor.requests, "get", fake_get)
    result = telegram_monitor.poll_telegram_channels({"channels": ["@public_news"], "offset": 100})
    assert len(result["items"]) == 1
    assert result["items"][0]["url"] == "https://t.me/public_news/9"
    assert result["config"]["offset"] == 122
    assert "123456:" not in json.dumps(result)
    assert captured["params"]["offset"] == 100


def test_telegram_channel_names_reject_private_or_arbitrary_targets():
    assert telegram_monitor.normalize_public_channels("@newsroom, https://t.me/public_updates") == [
        "@newsroom", "@public_updates"]
    with pytest.raises(ValueError):
        telegram_monitor.normalize_public_channels("https://example.org/private-group")


def test_onion_monitor_requires_a_v3_onion_host_and_local_socks5h(monkeypatch):
    from smartintel import network
    with pytest.raises(ValueError, match="v3 .onion"):
        darkweb_monitor.fetch_onion_page("https://example.org/")
    monkeypatch.setattr(network, "configured_proxy_url", lambda: "socks5h://127.0.0.1:9050")
    proxy = darkweb_monitor._local_tor_proxy()
    assert proxy.scheme == "socks5h"
    monkeypatch.setattr(network, "configured_proxy_url", lambda: "socks5://127.0.0.1:9050")
    with pytest.raises(RuntimeError, match="socks5h"):
        darkweb_monitor._local_tor_proxy()


def test_content_monitor_persistence_and_telegram_single_cursor(tmp_path):
    store = Store(tmp_path / "content-monitor.sqlite3")
    user = store.create_user("monitor_admin", "very-long-password-123", "admin")
    case_id = store.create_case("Monitor case", owner_id=user)
    monitor_id = store.create_content_monitor(
        case_id, "bluesky_search", {"query": "public updates", "keywords": ["public"]},
        3600, user)
    rows = store.due_content_monitors()
    assert any(row["id"] == monitor_id and row["config"]["query"] == "public updates" for row in rows)
    assert store.record_content_monitor_item(monitor_id, "item-1") is True
    assert store.record_content_monitor_item(monitor_id, "item-1") is False
    store.create_content_monitor(case_id, "telegram_channels",
                                 {"channels": ["@channel_one"]}, 3600, user)
    with pytest.raises(ValueError, match="one Telegram monitor"):
        store.create_content_monitor(case_id, "telegram_channels",
                                     {"channels": ["@channel_two"]}, 3600, user)

def test_public_feed_monitor_rejects_secret_query_parameters():
    with pytest.raises(ValueError, match="must not embed authentication"):
        social_monitor.monitor_rss_feed("https://example.org/feed.xml?access_token=secret")


def test_onion_monitor_rejects_secret_query_parameters():
    url = "http://" + ("a" * 56) + ".onion/public?token=secret"
    with pytest.raises(ValueError, match="must not embed authentication"):
        darkweb_monitor.fetch_onion_page(url)
