from __future__ import annotations

import logging

import yaml

from vpnnode.models import Node

log = logging.getLogger(__name__)

AUTO_GROUP = "🚀 自动"
TRUSTED_GROUP = "⭐ 可信源"
ALL_GROUP = "📦 全部节点"
MANUAL_GROUP = "♻️ 手动"

# 长期存活、实测能用节点占比高的源。mahdibland 产出量最大但 97 个里只有 1 个
# 抗封锁协议，属于典型的「量大质低」，故意不列入。
TRUSTED_SOURCE_KEYS = (
    "ssrsub/ssr",
    "ermaozi/get_subscribe",
    "ripaojiedian/freenode",
    "leidahub.top",
    "yasserdivar/pr0xy",
    "icv2ray",
    "anaer/sub",
    "xiyaowong/freefq",
    "peasoft/nomorewalls",
)


def is_trusted_source(node: Node) -> bool:
    source = (node.source or "").lower()
    return any(key in source for key in TRUSTED_SOURCE_KEYS)
RESIDENTIAL_GROUP = "🏠 住宅 IP"
SAFE_GROUP = "🟢 安全"
FAST_GROUP = "⚡ 低延迟"

URLTEST_OPTS = {
    "type": "url-test",
    "url": "https://www.gstatic.com/generate_204",
    "interval": 300,
    "tolerance": 50,
}

COUNTRY_NAMES = {
    "HK": "香港", "TW": "台湾", "JP": "日本", "SG": "新加坡", "KR": "韩国",
    "US": "美国", "CA": "加拿大", "GB": "英国", "DE": "德国", "FR": "法国",
    "NL": "荷兰", "IT": "意大利", "ES": "西班牙", "CH": "瑞士", "SE": "瑞典",
    "NO": "挪威", "DK": "丹麦", "FI": "芬兰", "IE": "爱尔兰", "AT": "奥地利",
    "BE": "比利时", "PL": "波兰", "CZ": "捷克", "RO": "罗马尼亚", "UA": "乌克兰",
    "RU": "俄罗斯", "AU": "澳大利亚", "NZ": "新西兰", "IN": "印度", "TH": "泰国",
    "VN": "越南", "MY": "马来西亚", "ID": "印尼", "PH": "菲律宾", "TR": "土耳其",
    "AE": "阿联酋", "IL": "以色列", "SA": "沙特", "MX": "墨西哥", "BR": "巴西",
    "AR": "阿根廷", "CL": "智利", "ZA": "南非", "EG": "埃及", "BG": "保加利亚",
    "HR": "克罗地亚", "RS": "塞尔维亚", "SI": "斯洛文尼亚", "SK": "斯洛伐克",
    "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚", "MD": "摩尔多瓦",
    "BY": "白俄罗斯", "KZ": "哈萨克斯坦", "GE": "格鲁吉亚", "AM": "亚美尼亚",
    "AZ": "阿塞拜疆", "MN": "蒙古", "PK": "巴基斯坦", "BD": "孟加拉",
    "KH": "柬埔寨", "MM": "缅甸", "JO": "约旦", "KW": "科威特", "BH": "巴林",
    "OM": "阿曼", "NG": "尼日利亚", "KE": "肯尼亚", "MA": "摩洛哥",
    "TN": "突尼斯", "CO": "哥伦比亚", "PE": "秘鲁", "UY": "乌拉圭",
    "CR": "哥斯达黎加", "PA": "巴拿马", "GT": "危地马拉", "DO": "多米尼加",
    "PR": "波多黎各", "CY": "塞浦路斯", "IS": "冰岛", "LU": "卢森堡", "MT": "马耳他",
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


def country_label(country: str) -> str:
    """节点显示名用的地区前缀；未识别地区归入「其他」。"""
    key = (country or "").upper()
    label = COUNTRY_NAMES.get(key)
    return f"{_country_flag(key)} {label}" if label else "🌍 其他"


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
BOOL_FIELDS = {"tls", "udp", "skip-cert-verify", "tfo", "mptcp", "xudp",
               "reduce-rtt", "fast-open", "global-padding", "authenticated-length"}
DICT_FIELDS = {"ws-opts", "grpc-opts", "reality-opts", "xhttp-opts", "http-opts",
               "h2-opts", "plugin-opts", "smux"}


def _as_bool(value) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        return value.strip().lower() in ("1", "true", "yes", "on")
    return bool(value)


def _clean_field(field: str, value):
    """源数据里常见字符串形式的布尔值/错误的嵌套类型，内核会严格拒绝。"""
    if field in BOOL_FIELDS:
        return _as_bool(value)
    if field in DICT_FIELDS:
        return value if isinstance(value, dict) else None
    if field == "alpn":
        if isinstance(value, str):
            return [value]
        return value if isinstance(value, list) else None
    return value


def _to_clash(node: Node, name: str) -> dict:
    p = node.params
    proxy: dict = {}
    for field in PASSTHROUGH_FIELDS:
        if field in node.raw and field not in FORBIDDEN_FIELDS:
            value = _clean_field(field, node.raw[field])
            if value is not None:
                proxy[field] = value
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

    network = p.get("network")
    if network == "h2":
        h2_opts = dict(proxy.get("h2-opts") or {}) if isinstance(proxy.get("h2-opts"), dict) else {}
        if p.get("ws_path"):
            h2_opts["path"] = p["ws_path"]
        if p.get("ws_host"):
            h2_opts["host"] = [p["ws_host"]]
        if h2_opts:
            proxy["h2-opts"] = h2_opts
    elif network == "ws":
        ws_opts = dict(proxy.get("ws-opts") or {}) if isinstance(proxy.get("ws-opts"), dict) else {}
        if p.get("ws_path"):
            ws_opts["path"] = p["ws_path"]
        if p.get("ws_host"):
            headers = dict(ws_opts.get("headers") or {}) if isinstance(ws_opts.get("headers"), dict) else {}
            headers["Host"] = p["ws_host"]
            ws_opts["headers"] = headers
        if ws_opts:
            proxy["ws-opts"] = ws_opts

    return proxy


def is_resistant(node: Node) -> bool:
    """能否过 GFW 粗筛：明文传输（无 TLS 的 ss/vmess/vless）在国内基本必死。

    这是基于协议的判断，不依赖任何实测——GitHub Actions 在境外，
    测不出「境外能连、国内被墙」。
    """
    p = node.params
    if node.protocol == "hysteria2":
        return True
    if node.protocol == "trojan":
        return bool(p.get("tls", True))
    if p.get("security") == "reality" or p.get("reality_pbk"):
        return True
    return bool(p.get("tls"))


def _build_groups(nodes: list[Node], names: list[str]) -> list[dict]:
    resistant = [name for node, name in zip(nodes, names) if is_resistant(node)]
    # 抗封锁节点太少时不做拆分，否则默认组会只剩个位数
    auto_members = resistant if len(resistant) >= 10 else list(names)
    groups: list[dict] = [
        {**URLTEST_OPTS, "name": AUTO_GROUP, "proxies": auto_members},
    ]
    trusted = [name for node, name in zip(nodes, names) if is_trusted_source(node)]
    if trusted:
        groups.append({**URLTEST_OPTS, "name": TRUSTED_GROUP, "proxies": trusted})
    if resistant and len(resistant) < len(names):
        groups.append({**URLTEST_OPTS, "name": ALL_GROUP, "proxies": list(names)})

    # 按用途拆分的分组：空组不输出，避免客户端出现选不中的组
    tag_groups = [
        (RESIDENTIAL_GROUP, lambda p: p.get("ip_type") == "residential"),
        (SAFE_GROUP, lambda p: p.get("safety") == "safe"),
        (FAST_GROUP, lambda p: p.get("latency_level") == "fast"),
    ]
    for group_name, predicate in tag_groups:
        members = [name for node, name in zip(nodes, names) if predicate(node.params)]
        if members:
            groups.append({**URLTEST_OPTS, "name": group_name, "proxies": members})

    groups.append({"name": MANUAL_GROUP, "type": "select", "proxies": list(names) or ["DIRECT"]})

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
