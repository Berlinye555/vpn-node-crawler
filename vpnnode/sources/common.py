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


_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b[^>]*>.*?</\1\s*>", re.IGNORECASE | re.DOTALL)
_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_TAG_RE = re.compile(r"<[^>]*>")


def strip_html(text: str) -> str:
    """提取可见文本与链接地址，供从频道预览页等网页中抓取节点。

    删除标签而不是替换成空白：Telegram 有时把长 URI 拆进多个 span，
    直接删标签才能把链接接回去。
    """
    if not text:
        return ""
    text = _COMMENT_RE.sub(" ", text)
    text = _SCRIPT_STYLE_RE.sub(" ", text)
    links = _HREF_RE.findall(text)
    text = _TAG_RE.sub("", text)
    text = unescape_html(text)
    if links:
        text = text + "\n" + "\n".join(unescape_html(link) for link in links)
    return text


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
