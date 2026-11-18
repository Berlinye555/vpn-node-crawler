from __future__ import annotations

import logging

import yaml

from vpnnode.models import Node

log = logging.getLogger(__name__)

AUTO_GROUP = "🚀 自动"
MANUAL_GROUP = "♻️ 手动"


def _unique_names(nodes: list[Node]) -> list[str]:
    seen: dict[str, int] = {}
    names = []
    for node in nodes:
        base = node.name or node.server
        count = seen.get(base, 0)
        seen[base] = count + 1
        names.append(base if count == 0 else f"{base}-{count + 1}")
    return names


def _to_clash(node: Node, name: str) -> dict:
    p = node.params
    proxy: dict = {"name": name, "type": node.protocol, "server": node.server, "port": node.port}

    if node.protocol == "vmess":
        proxy.update(
            uuid=p.get("uuid", ""),
            alterId=int(p.get("alter_id") or 0),
            cipher=p.get("cipher", "auto"),
            network=p.get("network", "tcp"),
        )
        if p.get("tls"):
            proxy["tls"] = True
            proxy["servername"] = p.get("sni") or node.server
    elif node.protocol == "vless":
        proxy.update(
            uuid=p.get("uuid", ""),
            network=p.get("network", "tcp"),
        )
        if p.get("flow"):
            proxy["flow"] = p["flow"]
        if p.get("security") == "reality":
            proxy["tls"] = True
            proxy["servername"] = p.get("sni") or node.server
            proxy["reality-opts"] = {
                "public-key": p.get("reality_pbk", ""),
                "short-id": p.get("reality_sid", ""),
            }
        elif p.get("tls"):
            proxy["tls"] = True
            proxy["servername"] = p.get("sni") or node.server
    elif node.protocol == "trojan":
        proxy["password"] = p.get("password", "")
        if p.get("sni"):
            proxy["sni"] = p["sni"]
        proxy["network"] = p.get("network", "tcp")
    elif node.protocol == "ss":
        proxy.update(cipher=p.get("cipher", ""), password=p.get("password", ""))
    elif node.protocol == "hysteria2":
        proxy["password"] = p.get("password", "")
        if p.get("sni"):
            proxy["sni"] = p["sni"]

    ws_opts = {}
    if p.get("ws_path"):
        ws_opts["path"] = p["ws_path"]
    if p.get("ws_host"):
        ws_opts["headers"] = {"Host": p["ws_host"]}
    if ws_opts and p.get("network") in ("ws", "h2"):
        proxy["ws-opts"] = ws_opts

    return proxy


def _build_groups(nodes: list[Node], names: list[str]) -> list[dict]:
    groups: list[dict] = [
        {
            "name": AUTO_GROUP,
            "type": "url-test",
            "url": "https://www.gstatic.com/generate_204",
            "interval": 300,
            "tolerance": 50,
            "proxies": list(names),
        },
        {"name": MANUAL_GROUP, "type": "select", "proxies": list(names) or ["DIRECT"]},
    ]

    by_country: dict[str, list[str]] = {}
    for node, name in zip(nodes, names):
        country = node.params.get("country")
        if country:
            by_country.setdefault(str(country), []).append(name)
    for country, members in sorted(by_country.items()):
        groups.append({"name": f"🌍 {country}", "type": "url-test",
                       "url": "https://www.gstatic.com/generate_204",
                       "interval": 300, "proxies": members})
    return groups


RULES = [
    "DOMAIN-SUFFIX,local,DIRECT",
    "IP-CIDR,127.0.0.0/8,DIRECT",
    "IP-CIDR,10.0.0.0/8,DIRECT",
    "IP-CIDR,172.16.0.0/12,DIRECT",
    "IP-CIDR,192.168.0.0/16,DIRECT",
    "GEOIP,CN,DIRECT",
    f"MATCH,{AUTO_GROUP}",
]


def render_clash(nodes: list[Node], cfg: dict | None = None) -> str:
    names = _unique_names(nodes)
    proxies = [_to_clash(node, name) for node, name in zip(nodes, names)]
    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "proxies": proxies,
        "proxy-groups": _build_groups(nodes, names),
        "rules": RULES,
    }
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
