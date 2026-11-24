import asyncio

from vpnnode.filters import alive as alive_mod
from vpnnode.filters.alive import AliveResult, build_config, filter_alive
from vpnnode.models import Node


def _node(server: str) -> Node:
    return Node("ss", server, server, 8388, {"cipher": "aes-256-gcm", "password": "p"})


def test_filter_alive_by_success_rate():
    reliable, unstable, dead, untested = (_node("1.1.1.1"), _node("2.2.2.2"),
                                          _node("3.3.3.3"), _node("4.4.4.4"))
    results = {
        reliable.fingerprint: AliveResult(3, 3, 100),
        unstable.fingerprint: AliveResult(1, 3, 200),
        dead.fingerprint: AliveResult(0, 2, None),
    }
    kept, rejected = filter_alive([reliable, unstable, dead, untested], results, 0.66)
    assert kept == [reliable, untested]
    assert rejected == [(unstable, "unstable_proxy"), (dead, "dead_proxy")]


def test_alive_result_rate():
    assert AliveResult(2, 3).rate == 2 / 3
    assert AliveResult(0, 2).rate == 0.0
    assert AliveResult(0, 0).rate == 0.0


def test_build_config_uses_unique_ascii_names():
    nodes = [
        Node("ss", "美国 01", "1.1.1.1", 8388, {"cipher": "aes-256-gcm", "password": "p"}),
        Node("ss", "美国 01", "2.2.2.2", 8388, {"cipher": "aes-256-gcm", "password": "p"}),
    ]
    config, name_map = build_config(nodes)
    names = [proxy["name"] for proxy in config["proxies"]]
    assert names == ["n00000", "n00001"]
    assert set(name_map) == set(names)
    assert name_map["n00001"].server == "2.2.2.2"
    assert config["external-controller"].endswith(":19090")
    assert config["rules"] == ["MATCH,DIRECT"]


def test_check_alive_covers_all_nodes_across_batches(monkeypatch):
    """数千节点时分批测试，必须合并全部批次而不是只测前几批。"""
    nodes = [_node(f"10.0.{i}.1") for i in range(5)]

    async def fake_run_batch(batch, path, cfg, listen_base_port=None):
        return {node.fingerprint: AliveResult(1, 1, 100) for node in batch}

    monkeypatch.setattr(alive_mod, "_run_batch", fake_run_batch)
    result = asyncio.run(alive_mod.check_alive(nodes, "mihomo", {}, chunk_size=2))
    assert len(result) == 5


def test_check_alive_splits_rejected_batch(monkeypatch):
    """单批被内核拒绝时按 200 细分重试，不能整批丢弃。"""
    nodes = [_node(f"10.{i // 250}.{i % 250}.1") for i in range(250)]
    calls = []

    async def fake_run_batch(batch, path, cfg, listen_base_port=None):
        calls.append(len(batch))
        if len(batch) > 200:      # 模拟大配置被拒
            return None
        return {node.fingerprint: AliveResult(1, 1, 100) for node in batch}

    monkeypatch.setattr(alive_mod, "_run_batch", fake_run_batch)
    result = asyncio.run(alive_mod.check_alive(nodes, "mihomo", {}, chunk_size=250))
    assert calls[0] == 250            # 先整批
    assert len(result) == 250         # 细分成 200 + 50 后仍覆盖全部


def test_build_config_with_listeners():
    nodes = [_node("1.1.1.1"), _node("2.2.2.2")]
    config, name_map = build_config(nodes, listen_base_port=20000)
    listeners = config["listeners"]
    assert len(listeners) == 2
    assert listeners[0] == {"name": "l00000", "type": "mixed", "port": 20000,
                            "listen": "127.0.0.1", "proxy": "n00000"}
    assert listeners[1]["port"] == 20001
    assert listeners[1]["proxy"] == "n00001"
    assert set(listener["proxy"] for listener in listeners) == set(name_map)


def test_build_config_without_listeners():
    config, _ = build_config([_node("1.1.1.1")])
    assert "listeners" not in config


def test_build_config_keeps_protocol_fields():
    node = Node("vless", "n", "example.com", 443,
                {"uuid": "u", "network": "xhttp", "tls": True, "sni": "s.example.com"},
                raw={"type": "vless", "client-fingerprint": "chrome"})
    config, _ = build_config([node])
    proxy = config["proxies"][0]
    assert proxy["type"] == "vless"
    assert proxy["network"] == "xhttp"
    assert proxy["client-fingerprint"] == "chrome"
