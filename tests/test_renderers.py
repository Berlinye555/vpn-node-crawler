import base64

import yaml

from vpnnode.models import Node
from vpnnode.renderers.base64_sub import render_base64
from vpnnode.renderers.clash import is_resistant, render_clash


def sample_nodes():
    return [
        Node(
            protocol="vmess", name="HK-01", server="hk.example.com", port=443,
            params={"uuid": "u-1", "alter_id": 0, "cipher": "auto", "network": "ws",
                    "tls": True, "sni": "hk.example.com", "ws_path": "/ws", "ws_host": "cdn.example.com"},
            raw={},
        ),
        Node(
            protocol="trojan", name="JP-01", server="jp.example.com", port=443,
            params={"password": "pw", "tls": True, "network": "tcp", "sni": "jp.example.com"},
            raw={},
        ),
        Node(
            protocol="ss", name="SG-01", server="sg.example.com", port=8388,
            params={"cipher": "aes-256-gcm", "password": "pw2"}, raw={},
        ),
    ]


def test_render_clash_is_valid_yaml():
    text = render_clash(sample_nodes(), {})
    doc = yaml.safe_load(text)
    assert len(doc["proxies"]) == 3
    assert doc["proxies"][0]["name"] == "HK-01"
    assert doc["proxies"][0]["type"] == "vmess"
    assert doc["proxies"][0]["ws-opts"]["path"] == "/ws"
    assert any(g["name"] == "🚀 自动" for g in doc["proxy-groups"])
    assert doc["rules"][-1].startswith("MATCH")


def test_render_clash_has_urltest_group():
    doc = yaml.safe_load(render_clash(sample_nodes(), {}))
    auto = next(g for g in doc["proxy-groups"] if g["name"] == "🚀 自动")
    assert auto["type"] == "url-test"
    assert auto["url"] == "https://www.gstatic.com/generate_204"
    assert len(auto["proxies"]) == 3


def test_render_clash_includes_client_perf_settings():
    doc = yaml.safe_load(render_clash(sample_nodes(), {}))
    assert doc["tcp-concurrent"] is True
    assert doc["unified-delay"] is True
    assert doc["dns"]["enhanced-mode"] == "fake-ip"
    assert "jsdelivr" in doc["geox-url"]["geosite"]
    assert doc["rules"][0] == "GEOSITE,private,DIRECT"
    assert doc["rules"][-1].startswith("MATCH")


def test_country_group_uses_flag_and_name():
    nodes = sample_nodes()
    nodes[0].params["country"] = "JP"
    nodes[1].params["country"] = "US"
    nodes[2].params["country"] = "XX"
    names = [g["name"] for g in yaml.safe_load(render_clash(nodes, {}))["proxy-groups"]]
    assert "🇯🇵 日本" in names
    assert "🇺🇸 美国" in names
    assert "🌍 XX" in names


def test_tag_groups_are_created():
    nodes = sample_nodes()
    nodes[0].params.update(ip_type="residential", safety="safe", latency_level="fast")
    nodes[1].params.update(ip_type="datacenter", safety="suspicious", latency_level="medium")
    nodes[2].params.update(ip_type="cdn", safety="safe", latency_level="slow")
    by_name = {g["name"]: g for g in yaml.safe_load(render_clash(nodes, {}))["proxy-groups"]}
    assert by_name["🏠 住宅 IP"]["proxies"] == ["HK-01"]
    assert by_name["🟢 安全"]["proxies"] == ["HK-01", "SG-01"]
    assert by_name["⚡ 低延迟"]["proxies"] == ["HK-01"]
    assert by_name["🏠 住宅 IP"]["type"] == "url-test"


def test_tag_groups_skipped_when_empty():
    names = [g["name"] for g in yaml.safe_load(render_clash(sample_nodes(), {}))["proxy-groups"]]
    assert "🏠 住宅 IP" not in names
    assert "🟢 安全" not in names
    assert "⚡ 低延迟" not in names


def test_is_resistant_by_protocol():
    assert is_resistant(Node("ss", "n", "1.1.1.1", 8388,
                              {"cipher": "aes-256-gcm", "password": "p"})) is False
    assert is_resistant(Node("vless", "n", "1.1.1.1", 443, {"uuid": "u"})) is False
    assert is_resistant(Node("vless", "n", "1.1.1.1", 443, {"uuid": "u", "tls": True})) is True
    assert is_resistant(Node("vless", "n", "1.1.1.1", 443,
                              {"uuid": "u", "security": "reality", "reality_pbk": "k"})) is True
    assert is_resistant(Node("trojan", "n", "1.1.1.1", 443, {"password": "p", "tls": True})) is True
    assert is_resistant(Node("hysteria2", "n", "1.1.1.1", 443, {"password": "p"})) is True


def test_auto_group_prefers_resistant_nodes():
    resistant = [Node("vless", f"r{i}", f"10.0.0.{i}", 443, {"uuid": f"u{i}", "tls": True})
                 for i in range(12)]
    plain = [Node("ss", f"p{i}", f"10.1.0.{i}", 8388,
                  {"cipher": "aes-256-gcm", "password": "p"}) for i in range(3)]
    groups = {g["name"]: g for g in yaml.safe_load(render_clash(resistant + plain, {}))["proxy-groups"]}
    assert len(groups["🚀 自动"]["proxies"]) == 12
    assert len(groups["📦 全部节点"]["proxies"]) == 15


def test_auto_group_falls_back_when_few_resistant():
    resistant = [Node("vless", f"r{i}", f"10.0.0.{i}", 443, {"uuid": f"u{i}", "tls": True})
                 for i in range(3)]
    plain = [Node("ss", f"p{i}", f"10.1.0.{i}", 8388,
                  {"cipher": "aes-256-gcm", "password": "p"}) for i in range(3)]
    groups = {g["name"]: g for g in yaml.safe_load(render_clash(resistant + plain, {}))["proxy-groups"]}
    assert len(groups["🚀 自动"]["proxies"]) == 6


def test_render_clash_empty_nodes():
    doc = yaml.safe_load(render_clash([], {}))
    assert doc["proxies"] == []


def test_render_passes_through_protocol_fields():
    node = Node(
        protocol="vless", name="Reality", server="r.example.com", port=443,
        params={"uuid": "u", "tls": True, "security": "reality", "sni": "r.example.com",
                "reality_pbk": "pbk", "reality_sid": "ab", "network": "tcp"},
        raw={"type": "vless", "client-fingerprint": "chrome",
             "reality-opts": {"public-key": "pbk", "short-id": "ab"},
             "sub_tag": "private-field"},
    )
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["client-fingerprint"] == "chrome"
    assert proxy["reality-opts"]["public-key"] == "pbk"
    assert "sub_tag" not in proxy


def test_render_normalizes_string_bools_and_bad_nesting():
    node = Node("vless", "x", "e.example.com", 443,
                {"uuid": "u", "tls": True, "network": "ws"},
                raw={"type": "vless", "tls": "true", "udp": "1",
                     "skip-cert-verify": "false", "alpn": "h2",
                     "ws-opts": "not-a-dict"})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["tls"] is True
    assert proxy["udp"] is True
    assert proxy["skip-cert-verify"] is False
    assert proxy["alpn"] == ["h2"]


def test_render_blocks_script_field():
    node = Node("vmess", "evil", "1.2.3.4", 443, {"uuid": "u"},
                raw={"type": "vmess", "script": "doEvil()"})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert "script" not in proxy


def test_render_hysteria2_obfs_and_updown():
    node = Node("hysteria2", "HY", "hy.example.com", 8443,
                {"password": "pw", "sni": "hy.example.com", "obfs": "salamander", "obfs_password": "s"},
                raw={"type": "hysteria2", "up": "50", "down": "100"})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["obfs"] == "salamander"
    assert proxy["obfs-password"] == "s"
    assert proxy["up"] == "50"


def test_render_grpc_opts():
    node = Node("vless", "GRPC", "g.example.com", 443,
                {"uuid": "u", "network": "grpc", "grpc_service": "svc"}, raw={})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["grpc-opts"]["grpc-service-name"] == "svc"


def test_render_h2_uses_h2_opts():
    node = Node("vless", "H2", "h.example.com", 443,
                {"uuid": "u", "network": "h2", "tls": True, "ws_path": "/x",
                 "ws_host": "cdn.example.com"}, raw={})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["h2-opts"]["path"] == "/x"
    assert proxy["h2-opts"]["host"] == ["cdn.example.com"]
    assert "ws-opts" not in proxy


def test_render_ws_opts_preserves_passthrough_extras():
    node = Node("vmess", "WS", "w.example.com", 443,
                {"uuid": "u", "network": "ws", "tls": True, "ws_path": "/new",
                 "ws_host": "cdn.example.com"},
                raw={"type": "vmess", "ws-opts": {"path": "/old", "max-early-data": 2048,
                                                 "headers": {"Host": "old.example.com"}}})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["ws-opts"]["path"] == "/new"
    assert proxy["ws-opts"]["headers"]["Host"] == "cdn.example.com"
    assert proxy["ws-opts"]["max-early-data"] == 2048


def test_render_ss_plugin():
    node = Node("ss", "SSP", "s.example.com", 8388,
                {"cipher": "aes-256-gcm", "password": "p", "plugin": "obfs",
                 "plugin_opts": {"mode": "http", "host": "h.example.com"}}, raw={})
    proxy = yaml.safe_load(render_clash([node], {}))["proxies"][0]
    assert proxy["plugin"] == "obfs"
    assert proxy["plugin-opts"]["host"] == "h.example.com"


def test_render_base64_roundtrip():
    text = render_base64(sample_nodes())
    decoded = base64.b64decode(text).decode()
    lines = [l for l in decoded.splitlines() if l.strip()]
    assert len(lines) == 3
    assert lines[0].startswith("vmess://")
    assert lines[1].startswith("trojan://")
    assert lines[2].startswith("ss://")
