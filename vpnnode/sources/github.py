from __future__ import annotations

import logging
import os

from vpnnode.fetch import fetch_text
from vpnnode.models import Node
from vpnnode.sources.common import parse_any_text

log = logging.getLogger(__name__)


async def fetch_source(spec: dict) -> list[Node]:
    """spec: {type: github, urls: [raw 链接, ...]}"""
    headers = {}
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    nodes: list[Node] = []
    for url in spec.get("urls", []):
        try:
            text = await fetch_text(url, headers=headers, timeout=float(spec.get("timeout", 20)))
        except Exception as exc:
            log.warning("github source failed: %s (%s)", url, exc)
            continue
        batch = parse_any_text(text)
        for node in batch:
            node.source = f"github:{url}"
        nodes.extend(batch)
        log.info("github %s -> %d nodes", url, len(batch))
    return nodes
