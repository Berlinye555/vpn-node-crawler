import asyncio

import pytest

from vpnnode.sources import telegram
from vpnnode.sources.common import strip_html

CHANNEL_HTML = """
<html><head><style>.hidden</style></head><body>
<div class="tgme_widget_message" data-post="chn/{old}">
  <div class="tgme_widget_message_text">ss://YWVzLTI1Ni1nY206cGFzcw==@1.2.3.4:8388#node{old}</div>
</div>
<div class="tgme_widget_message" data-post="chn/{new}">
  <div class="tgme_widget_message_text">trojan://pw@5.6.7.8:443?sni=a.com&amp;type=ws#node{new}</div>
</div>
<script>var fake = "vmess://should-not-appear";</script>
</body></html>
"""


def test_strip_html_keeps_uri_and_unescapes():
    text = strip_html('<div>a&amp;b</div><span>ss://x@1.2.3.4:8388#n</span>')
    assert "a&b" in text
    assert "ss://x@1.2.3.4:8388#n" in text
    assert "<span" not in text


def test_strip_html_removes_script_and_style():
    text = strip_html("<style>.a{}</style><script>var x='vmess://fake'</script>keep")
    assert "vmess://fake" not in text
    assert ".a{}" not in text
    assert "keep" in text


def test_strip_html_joins_uri_split_by_tags():
    # 标签夹在 URL 中间时，删除标签应把链接接回去
    text = strip_html("ss://YW<b>Vz</b>LTI1@1.2.3.4:8388#n")
    assert "ss://YWVzLTI1@1.2.3.4:8388#n" in text


def test_extract_oldest_id():
    html = ('<div data-post="chn/105"></div><div data-post="chn/103"></div>'
            '<div data-post="chn/104"></div>')
    assert telegram._extract_oldest_id(html) == 103


def test_extract_oldest_id_none():
    assert telegram._extract_oldest_id("<div>no posts</div>") is None


def test_preview_url():
    assert telegram._preview_url("chn", None) == "https://t.me/s/chn"
    assert telegram._preview_url("chn", 99) == "https://t.me/s/chn?before=99"


def test_fetch_source_multi_channel_with_paging(monkeypatch):
    requested = []

    async def fake_fetch(url, **kwargs):
        requested.append(url)
        if "before=" in url:
            return CHANNEL_HTML.format(old=1, new=2)
        return CHANNEL_HTML.format(old=101, new=102)

    monkeypatch.setattr(telegram, "fetch_text", fake_fetch)
    spec = {"type": "telegram", "channels": ["chn"], "max_pages": 2}
    nodes = asyncio.run(telegram.fetch_source(spec))

    assert len(requested) == 2
    assert requested[0] == "https://t.me/s/chn"
    assert requested[1] == "https://t.me/s/chn?before=101"
    assert len(nodes) == 4
    assert {node.source for node in nodes} == {"telegram:chn"}


def test_fetch_source_single_channel_key(monkeypatch):
    async def fake_fetch(url, **kwargs):
        return CHANNEL_HTML.format(old=1, new=2)

    monkeypatch.setattr(telegram, "fetch_text", fake_fetch)
    nodes = asyncio.run(telegram.fetch_source({"type": "telegram", "channel": "@chn"}))
    assert len(nodes) == 2
    assert nodes[0].source == "telegram:chn"


def test_fetch_source_empty_channel():
    assert asyncio.run(telegram.fetch_source({"type": "telegram", "channel": ""})) == []


def test_fetch_source_raises_with_diagnostics_when_no_nodes(monkeypatch):
    async def fake_fetch(url, **kwargs):
        return "<html><body>Just a moment...</body></html>"

    monkeypatch.setattr(telegram, "fetch_text", fake_fetch)
    with pytest.raises(telegram.TelegramEmpty) as exc:
        asyncio.run(telegram.fetch_source({"type": "telegram", "channels": ["chn"]}))
    message = str(exc.value)
    assert "chn" in message
    assert '"bytes"' in message
    assert '"nodes": 0' in message
    assert '"channel_info": false' in message
