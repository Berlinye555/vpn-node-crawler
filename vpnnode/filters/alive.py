from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request

import yaml

from vpnnode.models import Node
from vpnnode.renderers.clash import _to_clash

log = logging.getLogger(__name__)

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


async def _wait_api(timeout: float = 15) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        code, _ = await asyncio.to_thread(_http_get, f"http://{API_HOST}:{API_PORT}/version", 1)
        if code == 200:
            return True
        await asyncio.sleep(0.2)
    return False


async def check_alive(nodes: list[Node], mihomo_path: str, cfg: dict | None = None) -> dict[str, int | None]:
    """用 mihomo 内核真实测试节点能否转发 HTTP 请求。

    返回 {fingerprint: 延迟毫秒 | None}；值为 None 表示节点不可用。
    内核无法启动时返回空 dict（调用方跳过这一层）。
    """
    cfg = cfg or {}
    if not nodes:
        return {}

    workdir = tempfile.mkdtemp(prefix="mihomo-alive-")
    config, name_map = build_config(nodes)
    config_path = pathlib.Path(workdir) / "config.yaml"
    config_path.write_text(yaml.safe_dump(config, allow_unicode=True, sort_keys=False), encoding="utf-8")

    try:
        proc = await asyncio.create_subprocess_exec(
            mihomo_path, "-f", str(config_path), "-d", workdir,
            stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
        )
    except Exception as exc:
        log.warning("mihomo launch failed: %s", exc)
        return {}

    try:
        if not await _wait_api():
            log.warning("mihomo API not ready, skip alive check")
            return {}

        timeout_ms = int(cfg.get("alive_timeout_ms", 6000))
        concurrency = int(cfg.get("alive_concurrency", 50))
        semaphore = asyncio.Semaphore(concurrency)
        encoded_url = urllib.parse.quote(TEST_URL, safe="")

        async def test(short: str) -> tuple[str, int | None]:
            async with semaphore:
                url = (f"http://{API_HOST}:{API_PORT}/proxies/{short}/delay"
                       f"?timeout={timeout_ms}&url={encoded_url}")
                code, body = await asyncio.to_thread(_http_get, url, timeout_ms / 1000 + 3)
                if code != 200:
                    return short, None
                try:
                    delay = int(json.loads(body).get("delay") or 0)
                except Exception:
                    return short, None
                return short, delay if delay > 0 else None

        pairs = await asyncio.gather(*(test(short) for short in name_map))
        results = {name_map[short].fingerprint: delay for short, delay in pairs}
        alive = sum(1 for delay in results.values() if delay)
        log.info("alive check: %d/%d nodes forward traffic", alive, len(results))
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
