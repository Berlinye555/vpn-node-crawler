from __future__ import annotations

import logging

import yaml

from vpnnode.models import Node

log = logging.getLogger(__name__)

AUTO_GROUP = "🚀 自动"
MANUAL_GROUP = "♻️ 手动"

COUNTRY_NAMES = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "KR": "韩国",
    "US": "美国", "CA": "加拿大", "GB": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "IT": "意大利", "ES": "西班牙", "CH": "瑞士", "SE": "瑞典",
    "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IE": "爱尔兰", "AT": "奥地利",
    "BE": "比利时", "PL": "波兰", "CZ": "捷克", "RO": "罗马尼亚", "UA": "乌克兰",
    "RU": "俄罗斯", "AU": "澳大利亚", "NZ": "新西兰", "IN": "印度", "TH": "泰国",
    "VN": "越南", "MY": "马来西亚", "ID": "印尼", "PH": "菲律宾", "TR": "土耳其",
    "AE": "阿联酋", "IL": "以色列", "SA": "沙特", "MX": "墨西哥", "BR": "巴西",
    "AR": "阿根廷", "CL": "智利", "ZA": "南非", "EG": "埃及",
}


def _country_flag(code: str) -> str:
    code = (code or "").upper()
    if len(code) != 2 or not code.isalpha():
        return "🌍"
    return "".join(chr(ord(char) + 0x1F1A5) for char in code)


def _group_name(country: str) -> str:
    key = (country or "").upper()
    label = COUNTRY_NAMES.get(key)
    return f"{_country_flag(key)} {label}" if label else f"🌍 {country}"


def _unique_names(nodes: list[Node]) -> list[str]:
    seen: dict[str, int] = {}
    names = []
    for node in nodes:
        base = node.name or node.server
        count = seen.get(base, 0)
        seen[base] = count + 1
        names.append(base if count == 0 else f"{base}-{count + 1}")
    return names


# 来自 Clash 源的节点原样保留这些标准字段（指纹、reality、obfs、grpc、插件等），
# 丢弃非标准私有字段，避免客户端解析报错。script/javascript 由 precheck 拦截，这里再兜一层。
PASSTHROUGH_FIELDS = {
    "tls", "servername", "sni", "network", "uuid", "password", "cipher", "alterId",
    "flow", "alpn", "udp", "skip-cert-verify", "client-fingerprint", "fingerprint",
    "ws-opts", "grpc-opts", "reality-opts", "xhttp-opts", "http-opts", "h2-opts",
    "plugin", "plugin-opts", "obfs", "obfs-password", "up", "down", "encryption",
    "packet-encoding", "auth", "auth-str", "username", "ports", "hop-interval",
}
FORBIDDEN_FIELDS = {"script", "javascript"}


def _to_clash(node: Node, name: str) -> dict:
    p = node.params
    proxy: dict = {}
    for field in PASSTHROUGH_FIELDS:
        if field in node.raw and field not in FORBIDDEN_FIELDS:
            proxy[field] = node.raw[field]
    proxy.update({"name": name, "type": node.protocol, "server": node.server, "port": node.port})

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
        if p.get("security") == "reality" or p.get("reality_pbk"):
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
        if p.get("plugin") and "plugin" not in proxy:
            proxy["plugin"] = p["plugin"]
            proxy["plugin-opts"] = p.get("plugin_opts") or {}
    elif node.protocol == "hysteria2":
        proxy["password"] = p.get("password", "")
        if p.get("sni"):
            proxy["sni"] = p["sni"]
        if p.get("obfs"):
            proxy["obfs"] = p["obfs"]
            proxy["obfs-password"] = p.get("obfs_password", "")

    if p.get("client_fingerprint") and "client-fingerprint" not in proxy:
        proxy["client-fingerprint"] = p["client_fingerprint"]
    if p.get("grpc_service") and "grpc-opts" not in proxy:
        proxy["grpc-opts"] = {"grpc-service-name": p["grpc_service"]}

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
        groups.append({"name": _group_name(country), "type": "url-test",
                       "url": "https://www.gstatic.com/generate_204",
                       "interval": 300, "proxies": members})
    return groups


RULES = [
    "GEOSITE,private,DIRECT",
    "GEOIP,private,DIRECT,no-resolve",
    "GEOSITE,cn,DIRECT",
    "GEOIP,CN,DIRECT",
    f"MATCH,{AUTO_GROUP}",
]

# geo 数据默认从 GitHub 下载，国内常失败；改用 jsDelivr 镜像
GEOX_URL = {
    "geoip": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat",
    "geosite": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat",
    "mmdb": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/country-lite.mmdb",
}

DNS = {
    "enable": True,
    "ipv6": False,
    "enhanced-mode": "fake-ip",
    "fake-ip-range": "198.18.0.1/16",
    "fake-ip-filter": [
        "*.lan",
        "*.local",
        "+.msftconnecttest.com",
        "+.msftncsi.com",
        "+.stun.*.*",
        "+.stun.*.*.*",
    ],
    "default-nameserver": ["223.5.5.5", "119.29.29.29"],
    "nameserver": ["https://223.5.5.5/dns-query", "https://doh.pub/dns-query"],
}


def render_clash(nodes: list[Node], cfg: dict | None = None) -> str:
    names = _unique_names(nodes)
    proxies = [_to_clash(node, name) for node, name in zip(nodes, names)]
    doc = {
        "mixed-port": 7890,
        "allow-lan": False,
        "mode": "rule",
        "log-level": "info",
        "ipv6": False,
        "tcp-concurrent": True,
        "unified-delay": True,
        "geox-url": GEOX_URL,
        "dns": DNS,
        "proxies": proxies,
        "proxy-groups": _build_groups(nodes, names),
        "rules": RULES,
    }
    return yaml.safe_dump(doc, allow_unicode=True, sort_keys=False)
