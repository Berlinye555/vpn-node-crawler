from __future__ import annotations

import re
import urllib.parse

from vpnnode.models import Node
from vpnnode.parsers.clash import parse_clash_yaml
from vpnnode.parsers.links import parse_text

CLASH_HINT_RE = re.compile(r"^\s*proxies:\s*$", re.MULTILINE)


def parse_any_text(text: str) -> list[Node]:
    """自动识别 Clash YAML / base64 订阅 / 明文链接三种格式。"""
    if not text:
        return []
    if CLASH_HINT_RE.search(text):
        nodes = parse_clash_yaml(text)
        if nodes:
            return nodes
    return parse_text(text)


def unescape_html(text: str) -> str:
    import html

    return html.unescape(text)


def extract_by_regex(text: str, pattern: str) -> str:
    try:
        matches = re.findall(pattern, text, re.DOTALL)
    except re.error:
        return text
    if not matches:
        return ""
    joined = []
    for match in matches:
        if isinstance(match, tuple):
            match = next((m for m in match if m), "")
        joined.append(str(match))
    return "\n".join(joined)


def quote_path(path: str) -> str:
    return urllib.parse.quote(path, safe="/?=&:;@,+-_.")
