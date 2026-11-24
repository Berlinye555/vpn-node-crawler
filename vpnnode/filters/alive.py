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
    exit_ip: str = ""
    exit_loc: str = ""
    warp: str = ""

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


def build_config(
    nodes: list[Node],
    listen_base_port: int | None = None,
) -> tuple[dict, dict[str, Node]]:
    """生成供 mihomo 加载的临时配置，节点名统一为短 ASCII 名避免编码问题。

    listen_base_port 非空时，为每个节点额外开一个本地 mixed 端口并钉死出口，
    供出口 IP 探测等真实请求使用；不传则只保留 delay API 测试所需的配置。
    """
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
    if listen_base_port:
        config["listeners"] = [
            {
                "name": f"l{index:05d}",
                "type": "mixed",
                "port": listen_base_port + index,
                "listen": API_HOST,
                "proxy": short,
            }
            for index, short in enumerate(name_map)
        ]
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
    listen_base_port: int | None = None,
) -> dict[str, AliveResult] | None:
    """跑一批节点；返回 None 表示内核因配置问题未能启动。"""
    workdir = tempfile.mkdtemp(prefix="mihomo-alive-")
    config, name_map = build_config(nodes, listen_base_port=listen_base_port)
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


async def check_alive(
    nodes: list[Node],
    mihomo_path: str,
    cfg: dict | None = None,
    chunk_size: int = 2000,
) -> dict[str, AliveResult]:
    """用 mihomo 内核真实请求验证节点。

    节点规模到数千时整批配置容易超出内核承受范围，所以先按 chunk_size 分批，
    每批独立起内核；单批被拒时再按 200 个一组细分，且覆盖全部节点而不是只测前几组。
    """
    cfg = cfg or {}
    if not nodes:
        return {}

    batches = [nodes[i:i + chunk_size] for i in range(0, len(nodes), chunk_size)]
    merged: dict[str, AliveResult] = {}
    for batch in batches:
        part = await _run_batch(batch, mihomo_path, cfg)
        if part is not None:
            merged.update(part)
            continue
        log.warning("batch of %d rejected by core, retrying in chunks of 200", len(batch))
        for start in range(0, len(batch), 200):
            sub = batch[start:start + 200]
            sub_result = await _run_batch(sub, mihomo_path, cfg)
            if sub_result:
                merged.update(sub_result)
    log.info("alive check done: %d/%d nodes tested", len(merged), len(nodes))
    return merged
