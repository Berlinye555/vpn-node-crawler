from __future__ import annotations

import asyncio
import logging
import pathlib
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

from vpnnode.models import Node

log = logging.getLogger(__name__)

# 该地址回显 Cloudflare 边缘看到的客户端 IP，即节点对外的真实出口。
EXIT_TRACE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
# 与 alive 的 external-controller(19090) / mixed-port(17890) 错开。
MIXED_BASE_PORT = 20000


def parse_trace(text: str) -> dict[str, str]:
    info = {"ip": "", "loc": "", "warp": ""}
    for line in text.splitlines():
        key, _, value = line.partition("=")
        if key in info:
            info[key] = value.strip()
    return info


def http_get_via_proxy(url: str, port: int, timeout: float) -> tuple[int, str]:
    """经本地 mixed 端口发 HTTP 请求；混合端口支持 HTTP CONNECT。"""
    proxy = f"http://127.0.0.1:{port}"
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy})
    )
    request = urllib.request.Request(url, headers={"User-Agent": "exit-probe"})
    try:
        with opener.open(request, timeout=timeout) as response:
            return response.status, response.read(4096).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(4096).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def probe_exit(port: int, timeout_ms: int = 5000) -> dict[str, str] | None:
    """返回 {ip, loc, warp}；拿不到出口 IP 时返回 None。"""
    code, body = http_get_via_proxy(EXIT_TRACE_URL, port, timeout_ms / 1000)
    if code != 200 or not body:
        return None
    info = parse_trace(body)
    return info if info["ip"] else None


async def probe_exits(
    nodes: list[Node],
    mihomo_path: str,
    cfg: dict | None = None,
) -> dict[str, dict[str, str]]:
    """对给定节点各开一个本地端口测真实出口，返回 {fingerprint: {ip, loc, warp}}。

    只在 alive 之后调用，且只应传入已确认可靠的节点。单个畸形节点会让整批配置
    被内核拒绝，所以按批启动，失败批不拖累其他批。
    """
    cfg = cfg or {}
    if not nodes:
        return {}

    batch_size = max(1, int(cfg.get("exit_probe_batch_size", 300)))
    merged: dict[str, dict[str, str]] = {}
    failed = 0
    for start in range(0, len(nodes), batch_size):
        batch = nodes[start:start + batch_size]
        part = await _probe_batch(batch, mihomo_path, cfg)
        if part is None:
            failed += 1
            log.warning("exit probe batch @%d failed (%d nodes)", start, len(batch))
            continue
        merged.update(part)
    if failed:
        log.warning("exit probe: %d batch(es) rejected by core", failed)
    return merged


async def _probe_batch(
    nodes: list[Node],
    mihomo_path: str,
    cfg: dict,
) -> dict[str, dict[str, str]] | None:
    """跑一批；返回 None 表示内核因配置问题未能启动。"""
    from vpnnode.filters.alive import _wait_api, build_config

    workdir = tempfile.mkdtemp(prefix="mihomo-exit-")
    config, _ = build_config(nodes, listen_base_port=MIXED_BASE_PORT)
    config_path = pathlib.Path(workdir) / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")

    log_path = pathlib.Path(workdir) / "mihomo.log"
    try:
        handle = open(log_path, "wb")
        try:
            proc = await asyncio.create_subprocess_exec(
                mihomo_path, "-f", str(config_path), "-d", workdir,
                stdout=handle, stderr=handle,
            )
        finally:
            handle.close()
    except Exception as exc:
        log.warning("exit probe launch failed: %s", exc)
        return None

    try:
        if not await _wait_api(proc):
            tail = ""
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
            except Exception:
                pass
            log.warning("exit probe mihomo not ready (exit=%s): %s", proc.returncode, tail)
            return None

        timeout_ms = int(cfg.get("exit_probe_timeout_ms", 5000))
        concurrency = int(cfg.get("exit_probe_concurrency", 30))
        semaphore = asyncio.Semaphore(concurrency)
        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=concurrency)

        async def one(index: int, node: Node) -> tuple[str, dict[str, str] | None]:
            async with semaphore:
                info = await loop.run_in_executor(
                    executor, probe_exit, MIXED_BASE_PORT + index, timeout_ms)
            return node.fingerprint, info

        try:
            pairs = await asyncio.gather(*(one(index, node) for index, node in enumerate(nodes)))
        finally:
            executor.shutdown(wait=False)

        result = {fingerprint: info for fingerprint, info in pairs if info}
        log.info("exit probe: %d/%d resolved", len(result), len(nodes))
        return result
    finally:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass
