from vpnnode.filters.precheck import precheck
from vpnnode.filters.probe import ProbeResult, build_ws_request, parse_http_status
from vpnnode.filters.quality import apply_quality
from vpnnode.models import Node

CFG = {
    "tls_policy": "strict",
    "tcp_fail_threshold": 2,
    "max_handshake_ms": 3000,
    "max_nodes_total": 300,
    "max_nodes_per_group": 30,
}


def mk(protocol="vmess", server="1.2.3.4", port=443, name="n", **params):
    base = {
        "vmess": {"uuid": "u-1", "network": "ws", "tls": True},
        "vless": {"uuid": "u-2", "network": "tcp", "tls": True},
        "trojan": {"password": "p", "tls": True},
        "ss": {"cipher": "aes-256-gcm", "password": "p"},
        "hysteria2": {"password": "p", "tls": True},
    }.get(protocol, {})
    base.update(params)
    return Node(protocol=protocol, name=name, server=server, port=port, params=base, raw={})


def reasons(rejected):
    return [r for _, r in rejected]


# ---------- precheck ----------

def test_precheck_passes_valid_nodes():
    nodes = [mk("vmess"), mk("vless", "2.2.2.2"), mk("trojan", "3.3.3.3"),
             mk("ss", "4.4.4.4"), mk("hysteria2", "5.5.5.5")]
    kept, rejected = precheck(nodes, CFG)
    assert len(kept) == 5
    assert rejected == []


def test_precheck_rejects_unsupported_protocol():
    kept, rejected = precheck([mk("http", "6.6.6.6"), mk("socks5", "7.7.7.7")], CFG)
    assert kept == []
    assert reasons(rejected) == ["unsupported_protocol", "unsupported_protocol"]


def test_precheck_rejects_allow_insecure():
    node = mk("trojan", "8.8.8.8", allow_insecure=True)
    kept, rejected = precheck([node], CFG)
    assert kept == []
    assert reasons(rejected) == ["insecure_tls"]


def test_precheck_rejects_script_field():
    node = mk("vmess", "9.9.9.9")
    node.raw = {"script": "doEvil()"}
    kept, rejected = precheck([node], CFG)
    assert kept == []
    assert reasons(rejected) == ["script_field"]

    node2 = mk("vmess", "9.9.9.9")
    node2.raw = {"javascript": "x"}
    _, rejected2 = precheck([node2], CFG)
    assert reasons(rejected2) == ["script_field"]


def test_precheck_rejects_private_and_reserved_addresses():
    hosts = ["127.0.0.1", "10.1.2.3", "192.168.1.1", "169.254.1.1", "0.0.0.0", "localhost", "a.internal"]
    nodes = [mk("vmess", h) for h in hosts]
    kept, rejected = precheck(nodes, CFG)
    assert kept == []
    assert set(reasons(rejected)) == {"private_address"}


def test_precheck_rejects_weak_ss_cipher():
    for cipher in ("none", "rc4-md5", "table", "chacha20"):
        node = mk("ss", "11.11.11.11", cipher=cipher)
        kept, rejected = precheck([node], CFG)
        assert kept == []
        assert reasons(rejected) == ["weak_cipher"]


def test_precheck_rejects_invalid_port():
    kept, rejected = precheck([mk("vmess", port=0), mk("vmess", port=70000)], CFG)
    assert kept == []
    assert reasons(rejected) == ["invalid_port", "invalid_port"]


def test_precheck_rejects_legacy_vless_flow():
    node = mk("vless", "1.1.1.1", flow="xtls-rprx-direct")
    kept, rejected = precheck([node], CFG)
    assert kept == []
    assert reasons(rejected) == ["unsupported_flow"]

    ok = mk("vless", "2.2.2.2", flow="xtls-rprx-vision")
    kept, _ = precheck([ok], CFG)
    assert len(kept) == 1


def test_precheck_rejects_missing_credentials():
    kept, rejected = precheck([mk("vmess", uuid=""), mk("trojan", password="")], CFG)
    assert kept == []
    assert reasons(rejected) == ["missing_credentials", "missing_credentials"]


# ---------- quality ----------

def pr(**kw):
    defaults = dict(ok=True, attempts=2, failures=0, handshake_ms=100, tls_ok=True)
    defaults.update(kw)
    return ProbeResult(**defaults)


def test_quality_rejects_connection_failures():
    nodes = [mk(server="1.1.1.1"), mk(server="2.2.2.2")]
    results = {
        nodes[0].fingerprint: pr(ok=True, handshake_ms=100),
        nodes[1].fingerprint: pr(ok=False, failures=2, handshake_ms=None, error="timeout"),
    }
    kept, rejected = apply_quality(nodes, results, CFG)
    assert [n.server for n in kept] == ["1.1.1.1"]
    assert reasons(rejected) == ["connect_failed"]


def test_quality_rejects_slow_handshake():
    node = mk(server="3.3.3.3")
    kept, rejected = apply_quality([node], {node.fingerprint: pr(handshake_ms=5000)}, CFG)
    assert kept == []
    assert reasons(rejected) == ["slow_handshake"]


def test_quality_rejects_ws_dead():
    node = mk("vless", "5.5.5.5", network="ws", tls=True)
    result = pr(ws_ok=False)
    kept, rejected = apply_quality([node], {node.fingerprint: result}, CFG)
    assert kept == []
    assert reasons(rejected) == ["ws_dead"]


def test_build_ws_request():
    req = build_ws_request("/path", "example.com", key="abc")
    assert req.startswith("GET /path HTTP/1.1\r\n")
    assert "Host: example.com\r\n" in req
    assert "Upgrade: websocket\r\n" in req
    assert "Sec-WebSocket-Key: abc\r\n" in req


def test_parse_http_status():
    assert parse_http_status(b"HTTP/1.1 101 Switching Protocols\r\n") == 101
    assert parse_http_status(b"HTTP/1.1 502 Bad Gateway\r\n") == 502
    assert parse_http_status(b"garbage\r\n") is None


def test_quality_rejects_missing_probe_result():
    node = mk(server="4.4.4.4")
    kept, rejected = apply_quality([node], {}, CFG)
    assert kept == []
    assert reasons(rejected) == ["not_probed"]


def test_quality_loose_keeps_self_signed():
    node = mk(server="5.5.5.5")
    result = pr(tls_ok=False, handshake_ms=100)
    kept, rejected = apply_quality([node], {node.fingerprint: result}, {**CFG, "tls_policy": "loose"})
    assert len(kept) == 1


def test_quality_strict_rejects_bad_cert():
    node = mk(server="6.6.6.6")
    result = pr(tls_ok=False, handshake_ms=100)
    kept, rejected = apply_quality([node], {node.fingerprint: result}, CFG)
    assert kept == []
    assert reasons(rejected) == ["bad_certificate"]


def test_quality_caps_total_and_per_group():
    cfg = {**CFG, "max_nodes_total": 3, "max_nodes_per_group": 2}
    nodes = [mk(server=f"7.7.7.{i}", name=f"n{i}") for i in range(1, 6)]
    for node, country in zip(nodes, ["HK", "HK", "HK", "JP", "JP"]):
        node.params["country"] = country
    results = {n.fingerprint: pr(handshake_ms=100 + i) for i, n in enumerate(nodes)}
    kept, rejected = apply_quality(nodes, results, cfg)
    # 组上限允许 2+2=4，总上限压到 3
    assert len(kept) == 3
    assert "over_total_limit" in reasons(rejected)


def test_quality_does_not_cap_nodes_without_country():
    cfg = {**CFG, "max_nodes_per_group": 2, "max_nodes_total": 100}
    nodes = [mk(server=f"9.9.9.{i}") for i in range(1, 6)]
    results = {n.fingerprint: pr(handshake_ms=100 + i) for i, n in enumerate(nodes)}
    kept, rejected = apply_quality(nodes, results, cfg)
    # 信誉查询失败/关闭时没有国家信息，不能被单组上限砍到 2
    assert len(kept) == 5
    assert rejected == []


def test_fingerprint_includes_cipher():
    a = mk("ss", "1.1.1.1", cipher="aes-256-gcm")
    b = mk("ss", "1.1.1.1", cipher="chacha20-ietf-poly1305")
    assert a.fingerprint != b.fingerprint


def test_quality_sorts_by_handshake():
    nodes = [mk(server="8.8.8.1"), mk(server="8.8.8.2")]
    results = {
        nodes[0].fingerprint: pr(handshake_ms=900),
        nodes[1].fingerprint: pr(handshake_ms=100),
    }
    kept, _ = apply_quality(nodes, results, CFG)
    assert [n.server for n in kept] == ["8.8.8.2", "8.8.8.1"]
