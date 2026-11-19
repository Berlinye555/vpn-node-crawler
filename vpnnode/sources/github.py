from __future__ import annotations

import logging
import os
import urllib.parse

from vpnnode.fetch import fetch_text
from vpnnode.models import Node
from vpnnode.sources.common import parse_any_text

log = logging.getLogger(__name__)

TOKEN_HOSTS = ("githubusercontent.com", "github.com")


def _headers_for(url: str) -> dict:
    """只对 GitHub 域名附加 token；镜像/CDN 等第三方不得拿到凭据。"""
    host = urllib.parse.urlsplit(url).hostname or ""
    token = os.environ.get("GITHUB_TOKEN")
    if token and any(host == allowed or host.endswith("." + allowed) for allowed in TOKEN_HOSTS):
        return {"Authorization": f"Bearer {token}"}
    return {}


async def fetch_source(spec: dict) -> list[Node]:
    """spec: {type: github, urls: [raw 链接, ...]}"""
    nodes: list[Node] = []
    for url in spec.get("urls", []):
        try:
            text = await fetch_text(url, headers=_headers_for(url), timeout=float(spec.get("timeout", 20)))
        except Exception as exc:
            log.warning("github source failed: %s (%s)", url, exc)
            continue
        batch = parse_any_text(text)
        for node in batch:
            node.source = f"github:{url}"
        nodes.extend(batch)
        log.info("github %s -> %d nodes", url, len(batch))
    return nodes
