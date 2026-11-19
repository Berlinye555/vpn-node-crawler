from __future__ import annotations

from vpnnode.filters.probe import ProbeResult
from vpnnode.models import Node

SORT_UNKNOWN = 10**6


def apply_quality(
    nodes: list[Node],
    results: dict[str, ProbeResult],
    cfg: dict | None = None,
) -> tuple[list[Node], list[tuple[Node, str]]]:
    cfg = cfg or {}
    max_ms = int(cfg.get("max_handshake_ms", 3000))
    fail_threshold = int(cfg.get("tcp_fail_threshold", 2))
    tls_policy = cfg.get("tls_policy", "strict")
    per_group = int(cfg.get("max_nodes_per_group", 30))
    total_limit = int(cfg.get("max_nodes_total", 300))

    kept: list[Node] = []
    rejected: list[tuple[Node, str]] = []
    passed: list[tuple[Node, ProbeResult]] = []

    for node in nodes:
        result = results.get(node.fingerprint)
        if result is None:
            rejected.append((node, "not_probed"))
            continue
        if not result.ok or result.failures >= fail_threshold:
            rejected.append((node, "connect_failed"))
            continue
        if result.tls_ok is False and tls_policy == "strict":
            rejected.append((node, "bad_certificate"))
            continue
        if result.ws_ok is False:
            rejected.append((node, "ws_dead"))
            continue
        if result.handshake_ms is not None and result.handshake_ms > max_ms:
            rejected.append((node, "slow_handshake"))
            continue
        if result.tls_ok is False:
            node.params["self_signed"] = True
        passed.append((node, result))

    passed.sort(key=lambda pair: pair[1].handshake_ms if pair[1].handshake_ms is not None else SORT_UNKNOWN)

    group_count: dict[str, int] = {}
    for node, _ in passed:
        if len(kept) >= total_limit:
            rejected.append((node, "over_total_limit"))
            continue
        country = str(node.params.get("country") or "")
        if country:
            if group_count.get(country, 0) >= per_group:
                rejected.append((node, "over_group_limit"))
                continue
            group_count[country] = group_count.get(country, 0) + 1
        # 无国家信息（信誉查询失败/关闭）时不套用单组上限，只受总量约束
        kept.append(node)

    return kept, rejected
