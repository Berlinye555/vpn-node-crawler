from __future__ import annotations

import asyncio
import json
import logging
import math
import pathlib
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

import yaml

from vpnnode.models import Node
from vpnnode.renderers.clash import _to_clash

log = logging.getLogger(__name__)


@dataclass
class AliveResult:
    success: int
    samples: int
    delay: int | None = None

    @property
    def rate(self) -> float:
        return self.success / self.samples if self.samples else 0.0


def filter_alive(
    nodes: list[Node],
    results: dict[str, AliveResult],
    min_rate: float,
) -> tuple[list[Node], list[tuple[Node, str]]]:
    """按真实请求成功率过滤；未测试到的节点保留。"""
    kept: list[Node] = []
    rejected: list[tuple[Node, str]] = []
    for node in nodes:
        result = results.get(node.fingerprint)
        if result is None or result.rate >= min_rate:
            kept.append(node)
            continue
        rejected.append((node, "dead_proxy" if result.success == 0 else "unstable_proxy"))
    return kept, rejected

API_HOST = "127.0.0.1"
API_PORT = 19090
MIXED_PORT = 17890
TEST_URL = "https://www.gstatic.com/generate_204"


def build_config(nodes: list[Node]) -> tuple[dict, dict[str, Node]]:
    """生成供 mihomo 加载的临时配置，节点名统一为短 ASCII 名避免编码问题。"""
    proxies = []
    name_map: dict[str, Node] = {}
    for index, node in enumerate(nodes):
        short = f"n{index:05d}"
        proxies.append(_to_clash(node, short))
        name_map[short] = node
    config = {
        "mixed-port": MIXED_PORT,
        "external-controller": f"{API_HOST}:{API_PORT}",
        "mode": "rule",
        "log-level": "silent",
        "proxies": proxies,
        "proxy-groups": [],
        "rules": ["MATCH,DIRECT"],
    }
    return config, name_map


def _http_get(url: str, timeout: float = 3) -> tuple[int, bytes]:
    request = urllib.request.Request(url, headers={"User-Agent": "alive-check"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read()
    except Exception:
        return 0, b""


async def _wait_api(proc, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            return False
        code, _ = await asyncio.to_thread(_http_get, f"http://{API_HOST}:{API_PORT}/version", 1)
        if code == 200:
            return True
        await asyncio.sleep(0.2)
    return False


async def _run_batch(
    nodes: list[Node],
    mihomo_path: str,
    cfg: dict,
) -> dict[str, AliveResult] | None:
    """跑一批节点；返回 None 表示内核因配置问题未能启动。"""
    workdir = tempfile.mkdtemp(prefix="mihomo-alive-")
    config, name_map = build_config(nodes)
    config_path = pathlib.Path(workdir) / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")

    log_path = pathlib.Path(workdir) / "mihomo.log"
    try:
        log_handle = open(log_path, "wb")
        try:
            proc = await asyncio.create_subprocess_exec(
                mihomo_path, "-f", str(config_path), "-d", workdir,
                stdout=log_handle, stderr=log_handle,
            )
        finally:
            log_handle.close()
    except Exception as exc:
        log.warning("mihomo launch failed: %s", exc)
        return None

    try:
        if not await _wait_api(proc):
            tail = ""
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-1200:]
            except Exception:
                pass
            log.warning("mihomo not ready (exit=%s): %s", proc.returncode, tail)
            return None

        timeout_ms = int(cfg.get("alive_timeout_ms", 6000))
        concurrency = int(cfg.get("alive_concurrency", 50))
        samples = max(1, int(cfg.get("alive_samples", 3)))
        min_rate = float(cfg.get("alive_min_success_rate", 0.66))
        needed = max(1, math.ceil(samples * min_rate))
        semaphore = asyncio.Semaphore(concurrency)
        encoded_url = urllib.parse.quote(TEST_URL, safe="")
        # 默认线程池在 2 核 runner 上只有 6 个线程，会把手动设置的并发压死
        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=concurrency)

        async def delay_once(short: str) -> int | None:
            url = (f"http://{API_HOST}:{API_PORT}/proxies/{short}/delay"
                   f"?timeout={timeout_ms}&url={encoded_url}")
            code, body = await loop.run_in_executor(
                executor, _http_get, url, timeout_ms / 1000 + 3)
            if code != 200:
                return None
            try:
                delay = int(json.loads(body).get("delay") or 0)
            except Exception:
                return None
            return delay if delay > 0 else None

        async def test(short: str) -> tuple[str, AliveResult]:
            async with semaphore:
                success = 0
                done = 0
                best: int | None = None
                for _ in range(samples):
                    done += 1
                    delay = await delay_once(short)
                    if delay:
                        success += 1
                        best = delay if best is None else min(best, delay)
                    if success >= needed:
                        break
                    if (done - success) > (samples - needed):
                        break
                return short, AliveResult(success, done, best)

        try:
            pairs = await asyncio.gather(*(test(short) for short in name_map))
        finally:
            executor.shutdown(wait=False)
        results = {name_map[short].fingerprint: result for short, result in pairs}
        reliable = sum(1 for result in results.values() if result.rate >= min_rate)
        log.info("alive check: %d/%d nodes reliable (samples=%d, min_rate=%.2f)",
                 reliable, len(results), samples, min_rate)
        return results
    finally:
        try:
            proc.terminate()
            await asyncio.wait_for(proc.wait(), timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


async def check_alive(nodes: list[Node], mihomo_path: str, cfg: dict | None = None) -> dict[str, AliveResult]:
    """用 mihomo 内核真实请求验证节点。

    整批配置被内核拒绝时，自动按 200 个一组降级重试，避免个别畸形节点让整层失效。
    """
    cfg = cfg or {}
    if not nodes:
        return {}

    result = await _run_batch(nodes, mihomo_path, cfg)
    if result is not None:
        return result

    log.warning("full batch rejected by core, retrying in chunks of 200")
    chunks = [nodes[i:i + 200] for i in range(0, len(nodes), 200)]
    if len(chunks) > 3:
        log.warning("too many chunks (%d), only first 3 are tested", len(chunks))
        chunks = chunks[:3]
    merged: dict[str, AliveResult] = {}
    for chunk in chunks:
        part = await _run_batch(chunk, mihomo_path, cfg)
        if part:
            merged.update(part)
    return merged
