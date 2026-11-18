import base64
import json

import pytest

from vpnnode.parsers.links import parse_text, parse_uri
from vpnnode.parsers.clash import parse_clash_yaml


def _b64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


def make_vmess(**overrides) -> str:
    payload = {
        "v": "2",
        "ps": "测试节点",
        "add": "1.2.3.4",
        "port": "443",
        "id": "11111111-2222-3333-4444-555555555555",
        "aid": "0",
        "scy": "auto",
        "net": "ws",
        "type": "none",
        "host": "cdn.example.com",
        "path": "/ws",
        "tls": "tls",
        "sni": "cdn.example.com",
    }
    payload.update(overrides)
    return "vmess://" + _b64(json.dumps(payload))


def test_parse_vmess():
    node = parse_uri(make_vmess())
    assert node is not None
    assert node.protocol == "vmess"
    assert node.server == "1.2.3.4"
    assert node.port == 443
    assert node.params["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert node.params["network"] == "ws"
    assert node.params["tls"] is True
    assert node.params["sni"] == "cdn.example.com"
    assert node.params["ws_path"] == "/ws"
    assert node.params["ws_host"] == "cdn.example.com"
    assert node.name == "测试节点"


def test_parse_vmess_without_padding():
    uri = make_vmess().rstrip("=")
    node = parse_uri(uri)
    assert node is not None
    assert node.server == "1.2.3.4"


def test_parse_vless_ws_tls():
    uri = (
        "vless://22222222-3333-4444-5555-666666666666@example.com:443"
        "?encryption=none&security=tls&sni=sni.example.com&type=ws"
        "&host=cdn.example.com&path=%2Fws%3Fed%3D2048&flow=xtls-rprx-vision"
        "#%E6%B5%8B%E8%AF%95VL"
    )
    node = parse_uri(uri)
    assert node is not None
    assert node.protocol == "vless"
    assert node.server == "example.com"
    assert node.port == 443
    assert node.params["uuid"] == "22222222-3333-4444-5555-666666666666"
    assert node.params["tls"] is True
    assert node.params["sni"] == "sni.example.com"
    assert node.params["network"] == "ws"
    assert node.params["ws_path"] == "/ws?ed=2048"
    assert node.params["ws_host"] == "cdn.example.com"
    assert node.params["flow"] == "xtls-rprx-vision"
    assert node.name == "测试VL"


def test_parse_trojan():
    uri = "trojan://p%40ssw0rd@trojan.example.com:443?sni=trojan.example.com&type=ws&path=%2Ft#TG"
    node = parse_uri(uri)
    assert node is not None
    assert node.protocol == "trojan"
    assert node.server == "trojan.example.com"
    assert node.port == 443
    assert node.params["password"] == "p@ssw0rd"
    assert node.params["sni"] == "trojan.example.com"
    assert node.params["network"] == "ws"
    assert node.params["ws_path"] == "/t"


def test_parse_ss_sip002():
    userinfo = base64.urlsafe_b64encode(b"aes-256-gcm:secret").decode().rstrip("=")
    node = parse_uri(f"ss://{userinfo}@ss.example.com:8388#SS%E8%8A%82%E7%82%B9")
    assert node is not None
    assert node.protocol == "ss"
    assert node.server == "ss.example.com"
    assert node.port == 8388
    assert node.params["cipher"] == "aes-256-gcm"
    assert node.params["password"] == "secret"
    assert node.name == "SS节点"


def test_parse_ss_legacy():
    payload = _b64("chacha20-ietf-poly1305:pass123@1.1.1.1:1234")
    node = parse_uri(f"ss://{payload}#legacy")
    assert node is not None
    assert node.protocol == "ss"
    assert node.server == "1.1.1.1"
    assert node.port == 1234
    assert node.params["cipher"] == "chacha20-ietf-poly1305"
    assert node.params["password"] == "pass123"


def test_parse_hysteria2():
    uri = "hysteria2://secret@hy.example.com:8443/?sni=hy.example.com&insecure=0#HY"
    node = parse_uri(uri)
    assert node is not None
    assert node.protocol == "hysteria2"
    assert node.server == "hy.example.com"
    assert node.port == 8443
    assert node.params["password"] == "secret"
    assert node.params["sni"] == "hy.example.com"


def test_parse_hy2_alias():
    node = parse_uri("hy2://secret@hy.example.com:8443#HY")
    assert node is not None
    assert node.protocol == "hysteria2"


def test_unknown_scheme_returns_none():
    assert parse_uri("ftp://example.com/file") is None
    assert parse_uri("not a uri") is None


def test_malformed_vmess_returns_none():
    assert parse_uri("vmess://not-base64!!!") is None
    assert parse_uri("vmess://" + _b64("{not json")) is None


def test_invalid_port_returns_none():
    assert parse_uri("trojan://pass@example.com:99999#bad") is None
    assert parse_uri("trojan://pass@example.com#bad") is None


def test_parse_text_extracts_links_from_noise():
    text = f"""
    每日更新：
    {make_vmess()}
    以及
    vless://aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee@x.example.com:443?security=tls#A
    订阅广告，忽略 me
    """
    nodes = parse_text(text)
    assert len(nodes) == 2
    assert {n.protocol for n in nodes} == {"vmess", "vless"}


def test_parse_text_handles_base64_subscription():
    inner = make_vmess() + "\n" + "trojan://pw@t.example.com:443#T"
    nodes = parse_text(_b64(inner))
    assert len(nodes) == 2


def test_parse_clash_yaml():
    doc = """
    proxies:
      - name: HK-01
        type: vmess
        server: hk.example.com
        port: 443
        uuid: 11111111-2222-3333-4444-555555555555
        alterId: 0
        cipher: auto
        tls: true
        servername: hk.example.com
        network: ws
        ws-opts:
          path: /ws
          headers:
            Host: cdn.example.com
      - name: JP-SS
        type: ss
        server: jp.example.com
        port: 8388
        cipher: aes-256-gcm
        password: pw
      - name: SG-HY
        type: hysteria2
        server: sg.example.com
        port: 8443
        password: pw2
        sni: sg.example.com
    """
    nodes = parse_clash_yaml(doc)
    assert len(nodes) == 3
    hk = nodes[0]
    assert hk.protocol == "vmess"
    assert hk.params["uuid"] == "11111111-2222-3333-4444-555555555555"
    assert hk.params["network"] == "ws"
    assert hk.params["ws_path"] == "/ws"
    assert hk.params["ws_host"] == "cdn.example.com"
    assert nodes[1].protocol == "ss"
    assert nodes[1].params["cipher"] == "aes-256-gcm"
    assert nodes[2].protocol == "hysteria2"


def test_clash_yaml_keeps_script_field_in_raw():
    doc = """
    proxies:
      - name: EVIL
        type: http
        server: evil.example.com
        port: 8080
        script: alert(1)
    """
    nodes = parse_clash_yaml(doc)
    assert len(nodes) == 1
    assert nodes[0].raw["script"] == "alert(1)"


def test_clash_yaml_invalid_returns_empty():
    assert parse_clash_yaml("not: [valid") == []
    assert parse_clash_yaml("proxies: []") == []


def test_fingerprint_dedup():
    a = parse_uri(make_vmess())
    b = parse_uri(make_vmess(ps="另一个名字"))
    assert a is not None and b is not None
    assert a.fingerprint == b.fingerprint
    c = parse_uri(make_vmess(add="5.6.7.8"))
    assert c is not None
    assert c.fingerprint != a.fingerprint
