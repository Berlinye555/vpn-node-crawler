import base64

import yaml

from vpnnode.models import Node
from vpnnode.renderers.base64_sub import render_base64
from vpnnode.renderers.clash import render_clash


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


def test_render_clash_empty_nodes():
    doc = yaml.safe_load(render_clash([], {}))
    assert doc["proxies"] == []


def test_render_base64_roundtrip():
    text = render_base64(sample_nodes())
    decoded = base64.b64decode(text).decode()
    lines = [l for l in decoded.splitlines() if l.strip()]
    assert len(lines) == 3
    assert lines[0].startswith("vmess://")
    assert lines[1].startswith("trojan://")
    assert lines[2].startswith("ss://")
