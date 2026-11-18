from __future__ import annotations

import base64
import hashlib
import json
import urllib.parse
from dataclasses import dataclass, field
from typing import Any

SUPPORTED_PROTOCOLS = ("vmess", "vless", "trojan", "ss", "hysteria2")


def _b64(data: str) -> str:
    return base64.b64encode(data.encode()).decode()


@dataclass
class Node:
    protocol: str
    name: str
    server: str
    port: int
    params: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)
    source: str = ""

    @property
    def fingerprint(self) -> str:
        credential = ""
        for key in ("uuid", "password", "auth"):
            value = self.params.get(key)
            if value:
                credential = str(value)
                break
        material = f"{self.protocol}|{self.server.lower()}|{self.port}|{credential}"
        return hashlib.sha256(material.encode()).hexdigest()[:32]

    def to_uri(self) -> str:
        """按协议生成标准分享链接，供 Base64 订阅使用。"""
        name = urllib.parse.quote(self.name or self.server, safe="")
        p = self.params
        proto = self.protocol
        if proto == "vmess":
            payload = {
                "v": "2",
                "ps": self.name,
                "add": self.server,
                "port": str(self.port),
                "id": p.get("uuid", ""),
                "aid": str(p.get("alter_id", 0)),
                "scy": p.get("cipher", "auto"),
                "net": p.get("network", "tcp"),
                "type": "none",
                "host": p.get("ws_host", ""),
                "path": p.get("ws_path", ""),
                "tls": "tls" if p.get("tls") else "",
                "sni": p.get("sni", ""),
                "alpn": p.get("alpn", ""),
            }
            return "vmess://" + _b64(json.dumps(payload, ensure_ascii=False))
        if proto == "vless":
            query = {
                "encryption": "none",
                "security": p.get("security", "tls" if p.get("tls") else "none"),
                "sni": p.get("sni", ""),
                "type": p.get("network", "tcp"),
                "path": p.get("ws_path", ""),
                "host": p.get("ws_host", ""),
                "flow": p.get("flow", ""),
            }
            return f"vless://{p.get('uuid', '')}@{self.server}:{self.port}?{urllib.parse.urlencode(query)}#{name}"
        if proto == "trojan":
            query = {
                "security": "tls",
                "sni": p.get("sni", ""),
                "type": p.get("network", "tcp"),
                "path": p.get("ws_path", ""),
                "host": p.get("ws_host", ""),
            }
            password = urllib.parse.quote(str(p.get("password", "")), safe="")
            return f"trojan://{password}@{self.server}:{self.port}?{urllib.parse.urlencode(query)}#{name}"
        if proto == "ss":
            userinfo = _b64(f"{p.get('cipher', '')}:{p.get('password', '')}")
            return f"ss://{userinfo}@{self.server}:{self.port}#{name}"
        if proto == "hysteria2":
            password = urllib.parse.quote(str(p.get("password", "")), safe="")
            query = urllib.parse.urlencode({"sni": p.get("sni", "")})
            return f"hysteria2://{password}@{self.server}:{self.port}/?{query}#{name}"
        raise ValueError(f"unsupported protocol: {proto}")
