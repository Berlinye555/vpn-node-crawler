from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import socket
import urllib.request

import dns.resolver

from vpnnode.models import Node

log = logging.getLogger(__name__)

IP_API_BATCH = "http://ip-api.com/batch?fields=status,countryCode,country,hosting,query,as"
DNSBL_HIT_CODES = {f"127.0.0.{i}" for i in range(2, 12)}
BATCH_SIZE = 100


async def _resolve(host: str) -> list[str]:
    try:
        infos = await asyncio.to_thread(socket.getaddrinfo, host, None)
    except Exception:
        return []
    addresses = set()
    for info in infos:
        ip = info[4][0]
        try:
            addresses.add(str(ipaddress.ip_address(ip)))
        except ValueError:
            continue
    return sorted(addresses)


def _query_ip_api(ips: list[str]) -> dict[str, dict]:
    try:
        payload = json.dumps([{"query": ip} for ip in ips]).encode()
        request = urllib.request.Request(
            IP_API_BATCH,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            rows = json.loads(response.read().decode())
    except Exception as exc:
        log.warning("ip-api batch failed: %s", exc)
        return {}
    return {row.get("query", ""): row for row in rows if row.get("status") == "success"}


def _dnsbl_check(ip: str, zones: list[str]) -> tuple[bool, bool]:
    """返回 (是否命中黑名单, 是否至少查询成功一次)。查询失败不应被当作"未命中"。"""
    try:
        parsed = ipaddress.ip_address(ip)
    except ValueError:
        return False, False
    if parsed.version != 4:
        return False, True
    reversed_ip = ".".join(reversed(str(parsed).split(".")))
    checked = False
    for zone in zones:
        try:
            answers = dns.resolver.resolve(f"{reversed_ip}.{zone}", "A", lifetime=2)
        except dns.resolver.NXDOMAIN:
            checked = True
            continue
        except Exception:
            continue
        checked = True
        if any(record.address in DNSBL_HIT_CODES for record in answers):
            return True, True
    return False, checked


async def apply_reputation(nodes: list[Node], cfg: dict | None = None) -> tuple[list[Node], list[tuple[Node, str]], dict]:
    cfg = cfg or {}
    if not cfg.get("reputation_enabled", True):
        return nodes, [], {"enabled": False}

    resolved: dict[str, list[str]] = {}
    hosts = {node.server for node in nodes}
    results = await asyncio.gather(*(_resolve(host) for host in hosts))
    resolved = dict(zip(hosts, results))

    unique_ips: list[str] = []
    for ips in resolved.values():
        for ip in ips:
            if ip not in unique_ips:
                unique_ips.append(ip)

    info: dict[str, dict] = {}
    for start in range(0, len(unique_ips), BATCH_SIZE):
        chunk = unique_ips[start:start + BATCH_SIZE]
        info.update(await asyncio.to_thread(_query_ip_api, chunk))
        if start + BATCH_SIZE < len(unique_ips):
            await asyncio.sleep(1.5)

    zones = list(cfg.get("dnsbl_zones") or ["zen.spamhaus.org"])
    dnsbl_checks = await asyncio.gather(
        *(asyncio.to_thread(_dnsbl_check, ip, zones) for ip in unique_ips)
    )
    hit_ips = {ip for ip, (hit, _) in zip(unique_ips, dnsbl_checks) if hit}
    dnsbl_unverified = sum(1 for _, (_, checked) in zip(unique_ips, dnsbl_checks) if not checked)

    kept: list[Node] = []
    rejected: list[tuple[Node, str]] = []
    unverified = 0
    for node in nodes:
        ips = resolved.get(node.server, [])
        if not ips:
            unverified += 1
            node.params["reputation"] = "unverified"
            kept.append(node)
            continue
        if any(ip in hit_ips for ip in ips):
            rejected.append((node, "dnsbl_hit"))
            continue
        primary = info.get(ips[0]) or {}
        if primary:
            node.params["country"] = primary.get("countryCode") or primary.get("country") or ""
            node.params["hosting"] = bool(primary.get("hosting"))
            node.params["asn"] = primary.get("as") or ""
        kept.append(node)

    stats = {
        "enabled": True,
        "resolved_ips": len(unique_ips),
        "dnsbl_hits": len(hit_ips),
        "dnsbl_unverified": dnsbl_unverified,
        "unverified": unverified,
        "rejected": len(rejected),
    }
    return kept, rejected, stats
