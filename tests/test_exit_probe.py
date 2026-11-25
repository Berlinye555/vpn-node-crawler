import asyncio

from vpnnode.filters import exit_probe as ep_mod
from vpnnode.filters.exit_probe import parse_trace
from vpnnode.models import Node

TRACE = """fl=881f2
h=www.cloudflare.com
ip=203.0.113.9
ts=1795522395.123
visit_scheme=https
uag=Mozilla/5.0
colo=LAX
sliver=none
http=http/2
loc=JP
tls=TLSv1.3
sni=plaintext
warp=on"""


def test_parse_trace_fields():
    info = parse_trace(TRACE)
    assert info["ip"] == "203.0.113.9"
    assert info["loc"] == "JP"
    assert info["warp"] == "on"


def test_parse_trace_ignores_unknown_lines():
    info = parse_trace("foo=bar\nip=1.2.3.4\nnothing here")
    assert info == {"ip": "1.2.3.4", "loc": "", "warp": ""}


def test_parse_trace_empty():
    assert parse_trace("") == {"ip": "", "loc": "", "warp": ""}


def _node(server: str) -> Node:
    return Node("ss", server, server, 8388, {"cipher": "aes-256-gcm", "password": "p"})


def test_probe_exits_batches_and_isolates_failures(monkeypatch):
    """一批配置被内核拒绝时，不能拖累其他批。"""
    nodes = [_node(f"10.0.0.{i}") for i in range(5)]
    calls = []

    async def fake_batch(batch, path, cfg):
        calls.append(len(batch))
        if len(batch) > 2:
            return None
        return {node.fingerprint: {"ip": "1.2.3.4", "loc": "US", "warp": ""} for node in batch}

    monkeypatch.setattr(ep_mod, "_probe_batch", fake_batch)
    result = asyncio.run(ep_mod.probe_exits(nodes, "mihomo", {"exit_probe_batch_size": 3}))
    assert calls == [3, 2]
    assert len(result) == 2
