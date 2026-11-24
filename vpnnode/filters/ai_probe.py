from __future__ import annotations

import asyncio
import logging
import pathlib
import tempfile
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

from vpnnode.filters.alive import _wait_api, build_config
from vpnnode.filters.exit_probe import MIXED_BASE_PORT
from vpnnode.models import Node

log = logging.getLogger(__name__)

try:
    from curl_cffi import requests as _curl_requests
    HAS_CURL_CFFI = True
except ImportError:  # 没装就退回 urllib，判定精度下降但不会全部判死
    _curl_requests = None
    HAS_CURL_CFFI = False

# 健康状态码取自「无凭据的真实请求」：API 端点返回 401 说明 IP 没被封，只是没带 key。
TARGETS = {
    "openai_api": {"url": "https://api.openai.com/v1/models", "healthy": (401,)},
    "chatgpt": {"url": "https://chatgpt.com/cdn-cgi/trace", "healthy": (200,)},
    "anthropic_api": {"url": "https://api.anthropic.com/v1/models", "healthy": (401,)},
    "claude": {"url": "https://claude.ai/cdn-cgi/trace", "healthy": (200,)},
}

REGION_MARKERS = (
    "unsupported_country_region_territory",
    "not supported in your country",
    "country, region, or territory not supported",
)
CHALLENGE_MARKERS = (
    "challenges.cloudflare.com",
    "cf-chl",
    "just a moment",
    "attention required",
    "verifying you are human",
)
# 只认明确的封禁页。Anthropic 对部分出口返回 403 "Request not allowed"，
# 那是服务端策略而非 IP 脏，归 unknown 以免误判。
BLOCK_MARKERS = (
    "sorry, you have been blocked",
    "you have been blocked",
    "request blocked",
)


def classify(status: int, body: str, healthy) -> str:
    """把一次响应归到 健康/地区受限/CF 挑战/被拦/不通/无法判定。"""
    if status == 0:
        return "dead"
    lowered = (body or "").lower()
    if any(marker in lowered for marker in REGION_MARKERS):
        return "region_blocked"
    if any(marker in lowered for marker in CHALLENGE_MARKERS):
        return "challenge"
    if any(marker in lowered for marker in BLOCK_MARKERS):
        return "blocked"
    if status in healthy:
        return "ok"
    return "unknown"


def overall_level(levels: dict[str, str]) -> str:
    openai_ok = levels.get("openai_api") == "ok" or levels.get("chatgpt") == "ok"
    claude_ok = levels.get("anthropic_api") == "ok" or levels.get("claude") == "ok"
    if openai_ok and claude_ok:
        return "clean"
    if not openai_ok and not claude_ok:
        if all(levels.get(name) == "dead" for name in TARGETS):
            return "dead"
        return "blocked"
    return "partial"


def _urllib_get(url: str, proxy: str, timeout_s: float) -> tuple[int, str]:
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"})
    try:
        with opener.open(request, timeout=timeout_s) as response:
            return response.status, response.read(2000).decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(2000).decode("utf-8", "replace")
    except Exception:
        return 0, ""


def _fetch(url: str, port: int, timeout_s: float) -> tuple[int, str]:
    proxy = f"http://127.0.0.1:{port}"
    if _curl_requests is None:
        return _urllib_get(url, proxy, timeout_s)
    try:
        response = _curl_requests.get(
            url,
            impersonate="chrome",
            proxies={"http": proxy, "https": proxy},
            timeout=timeout_s,
            allow_redirects=True,
        )
        return response.status_code, (response.text or "")[:2000]
    except Exception:
        return 0, ""


def probe_node(port: int, timeout_s: float) -> dict[str, tuple[int, str]]:
    """经本地端口请求各 AI 端点，返回 {target: (status, body)}。"""
    return {name: _fetch(target["url"], port, timeout_s) for name, target in TARGETS.items()}


async def _run(nodes: list[Node], mihomo_path: str, cfg: dict) -> dict[str, dict[str, str]] | None:
    workdir = tempfile.mkdtemp(prefix="mihomo-ai-")
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
        log.warning("ai probe mihomo launch failed: %s", exc)
        return None

    try:
        if not await _wait_api(proc):
            tail = ""
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-800:]
            except Exception:
                pass
            log.warning("ai probe mihomo not ready (exit=%s): %s", proc.returncode, tail)
            return None

        timeout_ms = int(cfg.get("ai_probe_timeout_ms", 8000))
        concurrency = int(cfg.get("ai_probe_concurrency", 20))
        semaphore = asyncio.Semaphore(concurrency)
        loop = asyncio.get_running_loop()
        executor = ThreadPoolExecutor(max_workers=concurrency)

        async def one(index: int, node: Node) -> tuple[str, dict[str, str]]:
            async with semaphore:
                raw = await loop.run_in_executor(
                    executor, probe_node, MIXED_BASE_PORT + index, timeout_ms / 1000)
            levels = {
                name: classify(status, body, TARGETS[name]["healthy"])
                for name, (status, body) in raw.items()
            }
            return node.fingerprint, levels

        try:
            pairs = await asyncio.gather(*(one(index, node) for index, node in enumerate(nodes)))
        finally:
            executor.shutdown(wait=False)

        result = dict(pairs)
        for level in ("clean", "partial", "blocked", "dead"):
            count = sum(1 for levels in result.values() if overall_level(levels) == level)
            log.info("ai probe %s: %d", level, count)
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


async def check_ai(nodes: list[Node], mihomo_path: str, cfg: dict | None = None) -> dict[str, dict[str, str]]:
    cfg = cfg or {}
    if not nodes or not cfg.get("ai_probe_enabled", True):
        return {}
    result = await _run(nodes, mihomo_path, cfg)
    return result or {}
