from __future__ import annotations

import asyncio
import logging
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

from vpnnode.filters.reputation import _dnsbl_zones_hit, _query_ip_api
from vpnnode.models import Node

log = logging.getLogger(__name__)

# 出口落在这些 CDN 上时，出口 IP 是边缘节点而不是真实落地，不参与住宅/机房判定
CDN_KEYWORDS = (
    "cloudflare", "akamai", "fastly", "cloudfront", "gcore", "bunnycdn", "cdn77",
    "stackpath", "imperva", "incapsula", "quantil", "cachefly", "edgecast", "azurefd",
)

SAFETY_TAGS = {"safe": "🟢", "suspicious": "🟡", "unsafe": "🔴"}
LATENCY_TAGS = {"fast": "⚡", "slow": "🐢"}
IP_TAGS = {"residential": "🏠", "cdn": "☁️"}


def classify_ip(info: dict) -> str:
    if not info:
        return "unknown"
    asn = str(info.get("as") or "").lower()
    if any(keyword in asn for keyword in CDN_KEYWORDS):
        return "cdn"
    if info.get("mobile"):
        return "mobile"
    if info.get("hosting"):
        return "datacenter"
    if info.get("country") or info.get("countryCode") or asn:
        return "residential"
    return "unknown"


def safety_level(node: Node) -> str:
    p = node.params
    if p.get("self_signed") or p.get("allow_insecure"):
        return "unsafe"
    if p.get("proxy") or p.get("hosting"):
        return "suspicious"
    return "safe"


def latency_level(ms, fast_ms: int = 300, slow_ms: int = 800) -> str:
    if ms is None:
        return "unknown"
    if ms < fast_ms:
        return "fast"
    if ms > slow_ms:
        return "slow"
    return "medium"


def ip_score(node: Node) -> int:
    p = node.params
    score = 100
    if p.get("proxy"):
        score -= 40
    if p.get("hosting"):
        score -= 25
    if p.get("dnsbl_hit"):
        score -= 35
    if p.get("self_signed"):
        score -= 20
    return max(0, score)


def apply_tags(node: Node) -> list[str]:
    """节点名只挂最有信息量的两个标签：安全等级 + 特殊 IP 类型 + 快慢。"""
    p = node.params
    tags = [SAFETY_TAGS.get(p.get("safety"), "❔")]
    ip_tag = IP_TAGS.get(p.get("ip_type"))
    if ip_tag:
        tags.append(ip_tag)
    latency_tag = LATENCY_TAGS.get(p.get("latency_level"))
    if latency_tag:
        tags.append(latency_tag)
    return tags[:2]


async def _dnsbl_lookup(ips: list[str], zones: list[str]) -> tuple[set[str], dict[str, int]]:
    """返回 (命中任一列表的 IP 集合, 各列表命中次数)。后者用于识别误伤严重的列表。"""
    if not ips or not zones:
        return set(), {}
    loop = asyncio.get_running_loop()
    executor = ThreadPoolExecutor(max_workers=32)
    try:
        checks = await asyncio.gather(
            *(loop.run_in_executor(executor, _dnsbl_zones_hit, ip, zones) for ip in ips)
        )
    finally:
        executor.shutdown(wait=False)

    hit_ips: set[str] = set()
    by_zone: Counter = Counter()
    for ip, (zones_hit, _) in zip(ips, checks):
        if zones_hit:
            hit_ips.add(ip)
            by_zone.update(zones_hit)
    return hit_ips, dict(by_zone)


async def apply_intel(nodes: list[Node], cfg: dict | None = None) -> dict:
    """按出口 IP 补全地理/类型/风险信息，并给每个节点打安全与速度标签。

    只对已通过 alive 的节点调用，查询量受最终数量约束。
    """
    cfg = cfg or {}
    fast_ms = int(cfg.get("latency_fast_ms", 300))
    slow_ms = int(cfg.get("latency_slow_ms", 800))

    query_ips: list[str] = []
    for node in nodes:
        ip = node.params.get("exit_ip") or ""
        if ip and ip not in query_ips:
            query_ips.append(ip)

    info: dict[str, dict] = {}
    batch_size = int(cfg.get("intel_batch_size", 100))
    for start in range(0, len(query_ips), batch_size):
        chunk = query_ips[start:start + batch_size]
        info.update(await asyncio.to_thread(_query_ip_api, chunk))
        if start + batch_size < len(query_ips):
            await asyncio.sleep(1.5)

    hits, by_zone = await _dnsbl_lookup(query_ips, list(cfg.get("intel_dnsbl_zones") or []))

    for node in nodes:
        ip = node.params.get("exit_ip") or ""
        row = info.get(ip, {})
        if row:
            node.params["exit_country"] = row.get("countryCode") or ""
            node.params["country"] = row.get("countryCode") or node.params.get("country", "")
            node.params["asn"] = row.get("as") or node.params.get("asn", "")
            node.params["proxy"] = bool(row.get("proxy"))
            node.params["hosting"] = bool(row.get("hosting"))
        if ip and ip in hits:
            node.params["dnsbl_hit"] = True
        node.params["ip_type"] = classify_ip(row)
        node.params["safety"] = safety_level(node)
        node.params["latency_level"] = latency_level(node.params.get("latency_ms"), fast_ms, slow_ms)
        node.params["ip_score"] = ip_score(node)
        node.params["tags"] = apply_tags(node)

    stats = {
        "queried": len(query_ips),
        "resolved": len(info),
        "dnsbl_hits": len(hits),
        "dnsbl_by_zone": by_zone,
        "by_ip_type": dict(Counter(node.params.get("ip_type") for node in nodes)),
        "by_safety": dict(Counter(node.params.get("safety") for node in nodes)),
        "by_latency": dict(Counter(node.params.get("latency_level") for node in nodes)),
        "ip_score_avg": round(
            sum(node.params.get("ip_score", 0) for node in nodes) / len(nodes), 1
        ) if nodes else 0,
    }
    log.info("intel: %d exit ips queried, %d resolved, %d dnsbl hits",
             stats["queried"], stats["resolved"], stats["dnsbl_hits"])
    return stats
