from __future__ import annotations

import base64
import json
import logging
import re
import urllib.parse

from vpnnode.models import Node

log = logging.getLogger(__name__)

URI_RE = re.compile(r"(?:vmess|vless|trojan|ss|hysteria2|hy2)://[^\s\"'<>]+", re.IGNORECASE)
BASE64_RE = re.compile(r"^[A-Za-z0-9+/=\-_]+$")


def _decode_b64(value: str) -> bytes:
    value = value.strip().replace("\n", "").replace("\r", "")
    value += "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value)


def _parse_port(value) -> int | None:
    try:
        port = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _truthy(value) -> bool:
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("1", "true", "tls", "reality", "yes")


def _clean_uri(uri: str) -> str:
    return uri.rstrip(".,;)]}")


def parse_uri(uri: str) -> Node | None:
    uri = _clean_uri(uri.strip())
    scheme = uri.split("://", 1)[0].lower()
    try:
        if scheme == "vmess":
            return _parse_vmess(uri)
        if scheme == "vless":
            return _parse_vless(uri)
        if scheme == "trojan":
            return _parse_trojan(uri)
        if scheme == "ss":
            return _parse_ss(uri)
        if scheme in ("hysteria2", "hy2"):
            return _parse_hysteria2(uri)
    except Exception as exc:  # 单条畸形数据不中断整体解析
        log.debug("parse failed for %s: %s", uri[:60], exc)
    return None


def _parse_vmess(uri: str) -> Node | None:
    payload = uri[len("vmess://"):].split("#", 1)[0]
    data = json.loads(_decode_b64(payload).decode("utf-8", "replace"))
    if not isinstance(data, dict):
        return None
    server = str(data.get("add", "")).strip()
    port = _parse_port(data.get("port"))
    if not server or port is None:
        return None
    network = str(data.get("net", "tcp") or "tcp")
    return Node(
        protocol="vmess",
        name=str(data.get("ps") or server),
        server=server,
        port=port,
        params={
            "uuid": str(data.get("id", "")),
            "alter_id": int(data.get("aid") or 0),
            "cipher": str(data.get("scy") or "auto"),
            "network": network,
            "tls": _truthy(data.get("tls")),
            "sni": str(data.get("sni") or data.get("host") or ""),
            "ws_path": str(data.get("path") or "/") if network in ("ws", "h2") else "",
            "ws_host": str(data.get("host") or "") if network in ("ws", "h2") else "",
            "alpn": str(data.get("alpn") or ""),
            "grpc_service": str(data.get("path") or "") if network == "grpc" else "",
        },
        raw=data,
    )


def _url_parts(uri: str):
    parsed = urllib.parse.urlsplit(uri)
    userinfo = ""
    if parsed.username is not None:
        userinfo = urllib.parse.unquote(parsed.username)
        if parsed.password:
            userinfo += ":" + urllib.parse.unquote(parsed.password)
    return parsed, userinfo


def _parse_vless(uri: str) -> Node | None:
    parsed, userinfo = _url_parts(uri)
    host = parsed.hostname
    port = _parse_port(parsed.port)
    if not userinfo or not host or port is None:
        return None
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    network = query.get("type", "tcp") or "tcp"
    security = query.get("security", "none")
    return Node(
        protocol="vless",
        name=urllib.parse.unquote(parsed.fragment) or host,
        server=host,
        port=port,
        params={
            "uuid": userinfo,
            "network": network,
            "tls": security in ("tls", "reality"),
            "security": security,
            "sni": query.get("sni") or query.get("host") or "",
            "ws_path": query.get("path", "") if network in ("ws", "h2") else "",
            "ws_host": query.get("host", "") if network in ("ws", "h2") else "",
            "flow": query.get("flow", ""),
            "alpn": query.get("alpn", ""),
            "client_fingerprint": query.get("fp", ""),
            "reality_pbk": query.get("pbk", ""),
            "reality_sid": query.get("sid", ""),
        },
        raw={"uri": uri, "query": query},
    )


def _parse_trojan(uri: str) -> Node | None:
    parsed, userinfo = _url_parts(uri)
    host = parsed.hostname
    port = _parse_port(parsed.port)
    if not userinfo or not host or port is None:
        return None
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    network = query.get("type", "tcp") or "tcp"
    return Node(
        protocol="trojan",
        name=urllib.parse.unquote(parsed.fragment) or host,
        server=host,
        port=port,
        params={
            "password": userinfo,
            "network": network,
            "tls": True,
            "sni": query.get("sni") or query.get("peer") or "",
            "ws_path": query.get("path", "") if network in ("ws", "h2") else "",
            "ws_host": query.get("host", "") if network in ("ws", "h2") else "",
            "allow_insecure": _truthy(query.get("allowInsecure", query.get("insecure", "0"))),
        },
        raw={"uri": uri, "query": query},
    )


def _parse_ss_plugin(plugin: str) -> tuple[str, dict] | tuple[str, str]:
    """SIP002 plugin 参数 → Clash 的 plugin / plugin-opts。"""
    if not plugin:
        return "", ""
    parts = plugin.split(";")
    plugin_name = parts[0].strip()
    opts: dict[str, str] = {}
    for part in parts[1:]:
        if "=" in part:
            key, value = part.split("=", 1)
            opts[key.strip()] = value.strip()
        elif part.strip():
            opts["mode"] = part.strip()
    if plugin_name in ("obfs-local", "simple-obfs", "obfs"):
        return "obfs", {"mode": opts.get("obfs", opts.get("mode", "http")), "host": opts.get("obfs-host", "")}
    if plugin_name == "v2ray-plugin":
        clash_opts: dict = {"mode": opts.get("mode", "websocket")}
        if opts.get("host"):
            clash_opts["host"] = opts["host"]
        if opts.get("path"):
            clash_opts["path"] = opts["path"]
        if opts.get("tls") in ("1", "true"):
            clash_opts["tls"] = True
        return "v2ray-plugin", clash_opts
    return plugin_name, opts


def _parse_ss(uri: str) -> Node | None:
    body = uri[len("ss://"):]
    fragment = ""
    if "#" in body:
        body, fragment = body.split("#", 1)
    name = urllib.parse.unquote(fragment)

    query: dict[str, str] = {}
    if "?" in body:
        body, query_str = body.split("?", 1)
        query = dict(urllib.parse.parse_qsl(query_str, keep_blank_values=True))

    if "@" in body:
        # SIP002: ss://base64(method:password)@host:port 或 ss://method:password@host:port
        userinfo, hostpart = body.rsplit("@", 1)
        if ":" not in userinfo:
            userinfo = _decode_b64(userinfo).decode("utf-8", "replace")
        else:
            userinfo = urllib.parse.unquote(userinfo)
        hostpart = hostpart.split("?", 1)[0].split("/", 1)[0]
        server, _, port_str = hostpart.rpartition(":")
        cipher, _, password = userinfo.partition(":")
    else:
        # 老格式: ss://base64(method:password@host:port)
        decoded = _decode_b64(body.split("?", 1)[0]).decode("utf-8", "replace")
        userinfo, _, hostpart = decoded.rpartition("@")
        cipher, _, password = userinfo.partition(":")
        server, _, port_str = hostpart.rpartition(":")

    port = _parse_port(port_str)
    if not server or not cipher or port is None:
        return None
    plugin_name, plugin_opts = _parse_ss_plugin(query.get("plugin", ""))
    params = {"cipher": cipher.strip(), "password": password, "tls": False, "network": "tcp"}
    if plugin_name:
        params["plugin"] = plugin_name
        params["plugin_opts"] = plugin_opts
    return Node(
        protocol="ss",
        name=name or server,
        server=server.strip("[]"),
        port=port,
        params=params,
        raw={"uri": uri, "query": query},
    )


def _parse_hysteria2(uri: str) -> Node | None:
    parsed, userinfo = _url_parts(uri)
    host = parsed.hostname
    port = _parse_port(parsed.port)
    if not host or port is None:
        return None
    query = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
    return Node(
        protocol="hysteria2",
        name=urllib.parse.unquote(parsed.fragment) or host,
        server=host,
        port=port,
        params={
            "password": userinfo,
            "tls": True,
            "network": "udp",
            "sni": query.get("sni", ""),
            "obfs": query.get("obfs", ""),
            "obfs_password": query.get("obfs-password", ""),
            "allow_insecure": _truthy(query.get("insecure", "0")),
        },
        raw={"uri": uri, "query": query},
    )


def parse_text(text: str) -> list[Node]:
    """从任意文本中提取节点：支持整体 base64 订阅和夹杂噪声的明文链接。"""
    if not text:
        return []

    stripped = re.sub(r"\s+", "", text)
    if len(stripped) > 16 and BASE64_RE.match(stripped):
        try:
            decoded = _decode_b64(stripped).decode("utf-8", "replace")
            if "://" in decoded:
                text = decoded
        except Exception:
            pass

    nodes = []
    for match in URI_RE.finditer(text):
        node = parse_uri(match.group(0))
        if node is not None:
            nodes.append(node)
    return nodes
