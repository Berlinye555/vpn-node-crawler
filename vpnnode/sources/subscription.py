from __future__ import annotations

import logging

from vpnnode.fetch import fetch_text
from vpnnode.models import Node
from vpnnode.sources.common import parse_any_text

log = logging.getLogger(__name__)


async def fetch_source(spec: dict) -> list[Node]:
    """spec: {type: subscription, url, headers?: {}}"""
    url = spec.get("url", "")
    if not url:
        return []
    try:
        text = await fetch_text(url, headers=spec.get("headers"), timeout=float(spec.get("timeout", 20)))
    except Exception as exc:
        log.warning("subscription source failed: %s (%s)", url, exc)
        return []
    nodes = parse_any_text(text)
    for node in nodes:
        node.source = f"subscription:{url}"
    log.info("subscription %s -> %d nodes", url, len(nodes))
    return nodes
