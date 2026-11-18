from __future__ import annotations

import logging

from vpnnode.fetch import fetch_text
from vpnnode.models import Node
from vpnnode.sources.common import parse_any_text, unescape_html

log = logging.getLogger(__name__)

PREVIEW_URL = "https://t.me/s/{channel}"


async def fetch_source(spec: dict) -> list[Node]:
    """spec: {type: telegram, channel: 频道名（不含 @）}"""
    channel = str(spec.get("channel", "")).lstrip("@").strip()
    if not channel:
        return []
    url = PREVIEW_URL.format(channel=channel)
    try:
        text = await fetch_text(url, timeout=float(spec.get("timeout", 20)))
    except Exception as exc:
        log.warning("telegram source failed: %s (%s)", channel, exc)
        return []
    nodes = parse_any_text(unescape_html(text))
    for node in nodes:
        node.source = f"telegram:{channel}"
    log.info("telegram %s -> %d nodes", channel, len(nodes))
    return nodes
