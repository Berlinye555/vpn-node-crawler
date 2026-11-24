import asyncio

from vpnnode.filters import intel as intel_mod
from vpnnode.filters.intel import (
    apply_intel, apply_tags, classify_ip, ip_score, latency_level, safety_level,
)
from vpnnode.models import Node


def _node(**params) -> Node:
    return Node("ss", "n", "1.1.1.1", 8388, params)


def test_classify_ip_cdn():
    assert classify_ip({"as": "AS13335 Cloudflare, Inc."}) == "cdn"
    assert classify_ip({"as": "AS20940 Akamai International"}) == "cdn"


def test_classify_ip_mobile():
    assert classify_ip({"as": "AS9808 China Mobile", "mobile": True}) == "mobile"


def test_classify_ip_datacenter():
    assert classify_ip({"as": "AS4134 CHINANET", "hosting": True}) == "datacenter"


def test_classify_ip_residential():
    assert classify_ip({"as": "AS4766 Korea Telecom", "hosting": False}) == "residential"


def test_classify_ip_unknown():
    assert classify_ip({}) == "unknown"


def test_safety_level():
    assert safety_level(_node()) == "safe"
    assert safety_level(_node(proxy=True)) == "suspicious"
    assert safety_level(_node(hosting=True)) == "suspicious"
    assert safety_level(_node(self_signed=True)) == "unsafe"
    assert safety_level(_node(allow_insecure=True)) == "unsafe"


def test_latency_level():
    assert latency_level(120) == "fast"
    assert latency_level(500) == "medium"
    assert latency_level(1500) == "slow"
    assert latency_level(None) == "unknown"


def test_latency_level_custom_thresholds():
    assert latency_level(400, fast_ms=500) == "fast"
    assert latency_level(400, slow_ms=300) == "slow"


def test_apply_tags_safe_fast():
    node = _node(safety="safe", latency_level="fast")
    assert apply_tags(node) == ["🟢", "⚡"]


def test_apply_tags_suspicious_residential():
    node = _node(safety="suspicious", latency_level="medium", ip_type="residential")
    assert apply_tags(node) == ["🟡", "🏠"]


def test_apply_tags_unsafe_slow():
    node = _node(safety="unsafe", latency_level="slow")
    assert apply_tags(node) == ["🔴", "🐢"]


def test_apply_tags_limits_to_two():
    node = _node(safety="safe", latency_level="slow", ip_type="residential")
    assert len(apply_tags(node)) == 2


def test_ip_score_penalties():
    assert ip_score(_node()) == 100
    assert ip_score(_node(proxy=True)) == 60
    assert ip_score(_node(hosting=True)) == 75
    assert ip_score(_node(proxy=True, hosting=True)) == 35


def test_dnsbl_by_zone_stats(monkeypatch):
    def fake_query(ips):
        return {ip: {"status": "success", "query": ip, "countryCode": "US",
                     "as": "AS1 Example", "hosting": False, "proxy": False}
                for ip in ips}

    def fake_zones_hit(ip, zones):
        return (["zen.spamhaus.org"] if ip == "1.1.1.1" else []), True

    monkeypatch.setattr(intel_mod, "_query_ip_api", fake_query)
    monkeypatch.setattr(intel_mod, "_dnsbl_zones_hit", fake_zones_hit)
    nodes = [_node(exit_ip="1.1.1.1"), _node(exit_ip="2.2.2.2")]
    stats = asyncio.run(apply_intel(nodes, {"intel_dnsbl_zones": ["zen.spamhaus.org"]}))

    assert stats["dnsbl_hits"] == 1
    assert stats["dnsbl_by_zone"] == {"zen.spamhaus.org": 1}
    assert nodes[0].params["dnsbl_hit"] is True
    assert "dnsbl_hit" not in nodes[1].params


def test_apply_intel_reads_ipapi_proxy_flag(monkeypatch):
    """ip-api 的 fields 一旦漏掉 proxy，风险分就会静默失真，这里锁住。"""
    def fake_query(ips):
        return {ip: {"status": "success", "query": ip, "countryCode": "US",
                     "as": "AS1 Example", "hosting": True, "proxy": True, "mobile": False}
                for ip in ips}

    monkeypatch.setattr(intel_mod, "_query_ip_api", fake_query)
    node = _node(exit_ip="1.2.3.4", latency_ms=100)
    stats = asyncio.run(apply_intel([node], {"intel_dnsbl_zones": []}))

    assert node.params["proxy"] is True
    assert node.params["ip_type"] == "datacenter"
    assert node.params["safety"] == "suspicious"
    assert node.params["ip_score"] == 35
    assert node.params["tags"] == ["🟡", "⚡"]
    assert stats["queried"] == 1
    assert stats["resolved"] == 1
