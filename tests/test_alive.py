from vpnnode.filters.alive import build_config
from vpnnode.models import Node


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
