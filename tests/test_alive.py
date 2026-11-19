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


def test_build_config_keeps_protocol_fields():
    node = Node("vless", "n", "example.com", 443,
                {"uuid": "u", "network": "xhttp", "tls": True, "sni": "s.example.com"},
                raw={"type": "vless", "client-fingerprint": "chrome"})
    config, _ = build_config([node])
    proxy = config["proxies"][0]
    assert proxy["type"] == "vless"
    assert proxy["network"] == "xhttp"
    assert proxy["client-fingerprint"] == "chrome"
