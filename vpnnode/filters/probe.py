from __future__ import annotations

import asyncio
import base64
import logging
import os
import re
import ssl
import time
from dataclasses import dataclass

from vpnnode.models import Node

log = logging.getLogger(__name__)


@dataclass
class ProbeResult:
    ok: bool
    attempts: int = 1
    failures: int = 0
    handshake_ms: int | None = None
    tls_ok: bool | None = None
    ws_ok: bool | None = None
    error: str = ""

    def merge(self, other: "ProbeResult") -> "ProbeResult":
        """同一节点多次探测的合并：任一成功即整体成功。"""
        if other.ok:
            return other
        return self


def _needs_tls(node: Node) -> bool:
    return bool(node.params.get("tls")) or node.protocol == "trojan"


def _is_reality(node: Node) -> bool:
    return node.params.get("security") == "reality" or bool(node.params.get("reality_pbk"))


def _is_udp(node: Node) -> bool:
    return node.protocol == "hysteria2"


async def _close(writer) -> None:
    try:
        writer.close()
    except Exception:
        pass
    try:
        await asyncio.wait_for(writer.wait_closed(), timeout=1)
    except Exception:
        pass


async def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        await _close(writer)
        return True, ""
    except asyncio.TimeoutError:
        return False, "timeout"
    except Exception as exc:
        return False, type(exc).__name__


async def _tls_connect(host: str, port: int, sni: str, timeout: float) -> tuple[bool, str]:
    """校验证书链；返回 (证书是否合法, 错误信息)。"""
    ctx = ssl.create_default_context()
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=sni or host),
            timeout=timeout,
        )
        await _close(writer)
        return True, ""
    except ssl.SSLCertVerificationError as exc:
        return False, f"cert:{str(exc)[:120]}"
    except asyncio.TimeoutError:
        return False, "tls_timeout"
    except Exception as exc:
        return False, f"tls:{type(exc).__name__}"


STATUS_RE = re.compile(rb"HTTP/\d(?:\.\d)?\s+(\d{3})")


def build_ws_request(path: str, host: str, key: str | None = None) -> str:
    key = key or base64.b64encode(os.urandom(16)).decode()
    return (
        f"GET {path or '/'} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\n"
        "Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        "Sec-WebSocket-Version: 13\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
        "\r\n"
    )


def parse_http_status(line: bytes) -> int | None:
    match = STATUS_RE.match(line)
    return int(match.group(1)) if match else None


async def _ws_probe(node: Node, timeout: float) -> tuple[bool | None, bool | None, str]:
    """真实 WebSocket 握手，判断中转后端是否存活。

    返回 (证书是否有效, ws 是否存活, 错误描述)。
    ws_ok=False 表示服务端明确拒绝（4xx/5xx）——CF 中转节点最常见的失效形态。
    """
    host, port = node.server, node.port
    use_tls = _needs_tls(node)
    sni = node.params.get("sni") or ""
    ws_host = node.params.get("ws_host") or sni or host
    path = node.params.get("ws_path") or "/"
    ctx = ssl.create_default_context() if use_tls else None

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host, port, ssl=ctx,
                server_hostname=(sni or host) if use_tls else None,
            ),
            timeout=timeout,
        )
    except ssl.SSLCertVerificationError as exc:
        return False, None, f"cert:{str(exc)[:100]}"
    except asyncio.TimeoutError:
        return None, None, "timeout"
    except Exception as exc:
        return None, None, f"connect:{type(exc).__name__}"

    cert_ok = True if use_tls else None
    try:
        writer.write(build_ws_request(path, ws_host).encode())
        await writer.drain()
        line = await asyncio.wait_for(reader.readline(), timeout=timeout)
    except asyncio.TimeoutError:
        return cert_ok, None, "timeout"
    except Exception as exc:
        return cert_ok, None, f"error:{type(exc).__name__}"
    finally:
        await _close(writer)

    status = parse_http_status(line)
    if status is None:
        return cert_ok, None, "bad_response"
    if status == 101:
        return cert_ok, True, ""
    if status >= 400:
        return cert_ok, False, f"http_{status}"
    return cert_ok, None, f"http_{status}"


async def _probe_once(node: Node, timeout: float) -> ProbeResult:
    start = time.monotonic()
    if _is_udp(node):
        return ProbeResult(ok=True, attempts=1, failures=0, handshake_ms=None, tls_ok=None, error="udp_unverified")

    if node.params.get("network") == "ws":
        cert_ok, ws_ok, error = await _ws_probe(node, timeout)
        elapsed = int((time.monotonic() - start) * 1000)
        if cert_ok is False:
            return ProbeResult(ok=True, attempts=1, failures=0, handshake_ms=elapsed,
                               tls_ok=False, error=error)
        if ws_ok is None and error.startswith(("connect:", "timeout")):
            return ProbeResult(ok=False, attempts=1, failures=1, handshake_ms=None, error=error)
        return ProbeResult(ok=True, attempts=1, failures=0, handshake_ms=elapsed,
                           tls_ok=cert_ok, ws_ok=ws_ok,
                           error=error if ws_ok is False else "")

    tcp_ok, tcp_error = await _tcp_connect(node.server, node.port, timeout)
    if not tcp_ok:
        return ProbeResult(ok=False, attempts=1, failures=1, handshake_ms=None, tls_ok=None, error=tcp_error)

    elapsed = int((time.monotonic() - start) * 1000)

    if not _needs_tls(node) or _is_reality(node):
        return ProbeResult(ok=True, attempts=1, failures=0, handshake_ms=elapsed, tls_ok=None)

    cert_ok, tls_error = await _tls_connect(node.server, node.port, node.params.get("sni", ""), timeout)
    elapsed = int((time.monotonic() - start) * 1000)
    if not cert_ok and not tls_error.startswith("cert:"):
        # 超时/重置等 TLS 连接失败：计入连接失败并可重试，不当作证书问题
        return ProbeResult(ok=False, attempts=1, failures=1, handshake_ms=None,
                           tls_ok=None, error=tls_error)
    return ProbeResult(
        ok=True,
        attempts=1,
        failures=0,
        handshake_ms=elapsed,
        tls_ok=cert_ok,
        error="" if cert_ok else tls_error,
    )


async def probe_nodes(nodes: list[Node], cfg: dict | None = None) -> dict[str, ProbeResult]:
    cfg = cfg or {}
    timeout = float(cfg.get("probe_timeout_s", 5))
    attempts = int(cfg.get("tcp_fail_threshold", 2))
    concurrency = int(cfg.get("probe_concurrency", 30))
    semaphore = asyncio.Semaphore(concurrency)

    async def run(node: Node) -> tuple[str, ProbeResult]:
        async with semaphore:
            result = await _probe_once(node, timeout)
            for _ in range(attempts - 1):
                if result.ok:
                    break
                result.failures += 1
                result = result.merge(await _probe_once(node, timeout))
            return node.fingerprint, result

    pairs = await asyncio.gather(*(run(n) for n in nodes))
    return dict(pairs)
