from __future__ import annotations

import logging
import urllib.error
import urllib.request

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
