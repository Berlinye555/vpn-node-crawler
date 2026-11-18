from __future__ import annotations

from collections import Counter

from vpnnode.models import Node

SOURCE_PRIORITY = {"github": 0, "subscription": 1, "webpage": 2, "telegram": 3, "offline": 9}


def _kind(node: Node) -> str:
    return node.source.split(":", 1)[0] if node.source else ""


def aggregate(nodes: list[Node]) -> tuple[list[Node], dict]:
    """按来源可信度优先去重，同一指纹保留优先级最高的一条。"""
    ordered = sorted(
        enumerate(nodes),
        key=lambda pair: (SOURCE_PRIORITY.get(_kind(pair[1]), 99), pair[0]),
    )
    seen: dict[str, Node] = {}
    duplicates = 0
    for _, node in ordered:
        fingerprint = node.fingerprint
        if fingerprint in seen:
            duplicates += 1
            continue
        seen[fingerprint] = node
    stats = {
        "input": len(nodes),
        "unique": len(seen),
        "duplicates": duplicates,
        "by_source": dict(Counter(_kind(n) for n in seen.values())),
        "by_protocol": dict(Counter(n.protocol for n in seen.values())),
    }
    return list(seen.values()), stats
