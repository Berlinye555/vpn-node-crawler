from __future__ import annotations

import ipaddress

from vpnnode.models import SUPPORTED_PROTOCOLS, Node

WEAK_SS_CIPHERS = {"none", "rc4", "rc4-md5", "table", "plain", "dummy", "chacha20", "aes-128-cfb"}
PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".home", ".localhost", ".invalid", ".test")
FORBIDDEN_RAW_FIELDS = ("script", "javascript")


def _is_private_host(host: str) -> bool:
    host = host.strip("[]").lower()
    if host in ("localhost", "localhost.localdomain"):
        return True
    if any(host.endswith(suffix) for suffix in PRIVATE_SUFFIXES):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_unspecified
        or ip.is_multicast
    )


def _has_credentials(node: Node) -> bool:
    p = node.params
    if node.protocol in ("vmess", "vless"):
        return bool(p.get("uuid"))
    if node.protocol in ("trojan", "hysteria2"):
        return bool(p.get("password"))
    if node.protocol == "ss":
        return bool(p.get("cipher") and p.get("password"))
    return True


def check_node(node: Node) -> str | None:
    """返回剔除原因；None 表示通过。"""
    if node.protocol not in SUPPORTED_PROTOCOLS:
        return "unsupported_protocol"
    if not (1 <= node.port <= 65535):
        return "invalid_port"
    if _is_private_host(node.server):
        return "private_address"
    if any(field in node.raw for field in FORBIDDEN_RAW_FIELDS):
        return "script_field"
    if node.params.get("allow_insecure"):
        return "insecure_tls"
    if not _has_credentials(node):
        return "missing_credentials"
    if node.protocol == "ss" and str(node.params.get("cipher", "")).lower() in WEAK_SS_CIPHERS:
        return "weak_cipher"
    return None


def precheck(nodes: list[Node], cfg: dict | None = None) -> tuple[list[Node], list[tuple[Node, str]]]:
    kept: list[Node] = []
    rejected: list[tuple[Node, str]] = []
    for node in nodes:
        reason = check_node(node)
        if reason is None:
            kept.append(node)
        else:
            rejected.append((node, reason))
    return kept, rejected
