from __future__ import annotations

import asyncio
import logging
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


async def _tcp_connect(host: str, port: int, timeout: float) -> tuple[bool, str]:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
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
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True, ""
    except ssl.SSLCertVerificationError as exc:
        return False, f"cert:{str(exc)[:120]}"
    except asyncio.TimeoutError:
        return False, "tls_timeout"
    except Exception as exc:
        return False, f"tls:{type(exc).__name__}"


async def _probe_once(node: Node, timeout: float) -> ProbeResult:
    start = time.monotonic()
    if _is_udp(node):
        return ProbeResult(ok=True, attempts=1, failures=0, handshake_ms=None, tls_ok=None, error="udp_unverified")

    tcp_ok, tcp_error = await _tcp_connect(node.server, node.port, timeout)
    if not tcp_ok:
        return ProbeResult(ok=False, attempts=1, failures=1, handshake_ms=None, tls_ok=None, error=tcp_error)

    elapsed = int((time.monotonic() - start) * 1000)

    if not _needs_tls(node) or _is_reality(node):
        return ProbeResult(ok=True, attempts=1, failures=0, handshake_ms=elapsed, tls_ok=None)

    cert_ok, tls_error = await _tls_connect(node.server, node.port, node.params.get("sni", ""), timeout)
    elapsed = int((time.monotonic() - start) * 1000)
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
