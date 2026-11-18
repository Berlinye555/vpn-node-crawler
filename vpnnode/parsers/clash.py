from __future__ import annotations

import logging
from typing import Any

import yaml

from vpnnode.models import Node

log = logging.getLogger(__name__)

_TYPE_MAP = {
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "ss": "ss",
    "hysteria2": "hysteria2",
    "hy2": "hysteria2",
}


def _port(value: Any) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _clash_to_node(proxy: dict) -> Node | None:
    """Clash proxy 条目 → Node。未知类型保留原 protocol，交由 precheck 剔除。"""
    if not isinstance(proxy, dict):
        return None
    server = str(proxy.get("server", "")).strip()
    port = _port(proxy.get("port"))
    if not server or port is None:
        return None

    raw_type = str(proxy.get("type", "")).lower()
    protocol = _TYPE_MAP.get(raw_type, raw_type)
    network = str(proxy.get("network", "tcp") or "tcp")
    ws_opts = proxy.get("ws-opts") or {}
    headers = ws_opts.get("headers") or {}
    reality = proxy.get("reality-opts") or {}

    params: dict[str, Any] = {
        "network": network,
        "tls": bool(proxy.get("tls")),
        "sni": str(proxy.get("servername") or proxy.get("sni") or ""),
        "alpn": ",".join(proxy.get("alpn") or []) if isinstance(proxy.get("alpn"), list) else str(proxy.get("alpn") or ""),
        "ws_path": str(ws_opts.get("path", "")),
        "ws_host": str(headers.get("Host", "")),
        "grpc_service": str((proxy.get("grpc-opts") or {}).get("grpc-service-name", "")),
        "allow_insecure": bool(proxy.get("skip-cert-verify")),
    }
    if protocol == "vmess":
        params.update(uuid=str(proxy.get("uuid", "")), alter_id=int(proxy.get("alterId") or 0),
                      cipher=str(proxy.get("cipher") or "auto"))
    elif protocol == "vless":
        params.update(uuid=str(proxy.get("uuid", "")), flow=str(proxy.get("flow", "")),
                      reality_pbk=str(reality.get("public-key", "")),
                      reality_sid=str(reality.get("short-id", "")))
        if reality:
            params["security"] = "reality"
            params["tls"] = True
    elif protocol == "trojan":
        params["password"] = str(proxy.get("password", ""))
    elif protocol == "ss":
        params.update(cipher=str(proxy.get("cipher", "")), password=str(proxy.get("password", "")))
    elif protocol == "hysteria2":
        params.update(password=str(proxy.get("password", "")), network="udp")

    return Node(
        protocol=protocol,
        name=str(proxy.get("name") or server),
        server=server,
        port=port,
        params=params,
        raw=dict(proxy),
    )


def parse_clash_yaml(text: str) -> list[Node]:
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError:
        return []
    if not isinstance(doc, dict):
        return []
    proxies = doc.get("proxies") or []
    if not isinstance(proxies, list):
        return []
    nodes = []
    for proxy in proxies:
        node = _clash_to_node(proxy)
        if node is not None:
            nodes.append(node)
    return nodes
