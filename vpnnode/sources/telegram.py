from __future__ import annotations

import asyncio
import json
import logging
import re

from vpnnode.fetch import fetch_text
from vpnnode.models import Node
from vpnnode.parsers.links import URI_RE
from vpnnode.sources.common import parse_any_text, strip_html

log = logging.getLogger(__name__)

PREVIEW_URL = "https://t.me/s/{channel}"
POST_ID_RE = re.compile(r'data-post="[^"/]+/(\d+)"')


class TelegramEmpty(Exception):
    """抓到了页面却解析不出节点。异常信息里带诊断，会写进 report.failed_sources。"""


def _preview_url(channel: str, before: int | None) -> str:
    url = PREVIEW_URL.format(channel=channel)
    return f"{url}?before={before}" if before else url


def _extract_oldest_id(html: str) -> int | None:
    """取本页最旧一条消息的 id，作为下一页的翻页锚点。"""
    ids = [int(match) for match in POST_ID_RE.findall(html)]
    return min(ids) if ids else None


def _diagnose(channel: str, page: int, html: str, cleaned: str, nodes: list[Node]) -> dict:
    return {
        "channel": channel,
        "page": page,
        "bytes": len(html),
        "messages": html.count("tgme_widget_message"),
        "channel_info": "tgme_channel_info" in html,
        "uri_in_html": len(URI_RE.findall(html)),
        "uri_in_text": len(URI_RE.findall(cleaned)),
        "nodes": len(nodes),
    }


async def _fetch_channel(channel: str, spec: dict, diag: list[dict]) -> list[Node]:
    max_pages = max(1, int(spec.get("max_pages", 1)))
    timeout = float(spec.get("timeout", 20))
    nodes: list[Node] = []
    before: int | None = None
    seen_anchors: set[int] = set()
    for page in range(1, max_pages + 1):
        url = _preview_url(channel, before)
        try:
            html = await fetch_text(url, timeout=timeout)
        except Exception as exc:
            log.warning("telegram source failed: %s (%s)", url, exc)
            diag.append({"channel": channel, "page": page, "error": str(exc)[:160]})
            break
        cleaned = strip_html(html)
        batch = parse_any_text(cleaned)
        for node in batch:
            node.source = f"telegram:{channel}"
        nodes.extend(batch)
        diag.append(_diagnose(channel, page, html, cleaned, batch))
        oldest = _extract_oldest_id(html)
        if oldest is None or oldest in seen_anchors:
            break
        seen_anchors.add(oldest)
        before = oldest
    return nodes


async def fetch_source(spec: dict) -> list[Node]:
    """spec: {type: telegram, channel: x} 或 {type: telegram, channels: [x, y], max_pages: N}"""
    raw = spec.get("channels")
    if isinstance(raw, str):
        raw = [raw]
    if not raw:
        raw = [spec.get("channel", "")]
    channels = [str(item).lstrip("@").strip() for item in raw]
    channels = [item for item in channels if item]
    if not channels:
        return []

    diag: list[dict] = []
    batches = await asyncio.gather(*(_fetch_channel(channel, spec, diag) for channel in channels))
    nodes = [node for batch in batches for node in batch]
    log.info("telegram %d channel(s) -> %d nodes", len(channels), len(nodes))
    empty_pages = [item for item in diag if item.get("nodes") == 0 or item.get("error")]
    if empty_pages:
        log.warning("telegram pages without nodes: %s",
                    json.dumps(empty_pages, ensure_ascii=False)[:800])
    if not nodes:
        raise TelegramEmpty(json.dumps(diag, ensure_ascii=False)[:900])
    return nodes
