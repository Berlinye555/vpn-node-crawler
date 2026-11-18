from __future__ import annotations

import base64

from vpnnode.models import Node


def render_base64(nodes: list[Node]) -> str:
    lines = [node.to_uri() for node in nodes]
    return base64.b64encode("\n".join(lines).encode("utf-8")).decode("ascii")
