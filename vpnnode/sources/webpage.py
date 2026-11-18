from __future__ import annotations

import logging

from vpnnode.fetch import fetch_text
from vpnnode.models import Node
from vpnnode.sources.common import extract_by_regex, parse_any_text, unescape_html

log = logging.getLogger(__name__)


async def fetch_source(spec: dict) -> list[Node]:
    """spec: {type: webpage, url, regex?: 提取规则, headers?: {}}"""
    url = spec.get("url", "")
    if not url:
        return []
    try:
        text = await fetch_text(url, headers=spec.get("headers"), timeout=float(spec.get("timeout", 20)))
    except Exception as exc:
        log.warning("webpage source failed: %s (%s)", url, exc)
        return []

    if spec.get("regex"):
        text = extract_by_regex(text, spec["regex"]) or ""
    nodes = parse_any_text(unescape_html(text))
    for node in nodes:
        node.source = f"webpage:{url}"
    log.info("webpage %s -> %d nodes", url, len(nodes))
    return nodes
