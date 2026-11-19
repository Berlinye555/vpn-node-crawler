from __future__ import annotations

import asyncio
import logging
import random
import urllib.request

log = logging.getLogger(__name__)

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0 Safari/537.36",
]

MAX_BYTES = 10 * 1024 * 1024


class FetchError(Exception):
    pass


def _fetch_sync(url: str, timeout: float, extra_headers: dict | None) -> str:
    headers = {
        "User-Agent": random.choice(USER_AGENTS),
        "Accept": "*/*",
        "Accept-Language": "zh-CN,zh;q=0.9,en;q=0.8",
    }
    if extra_headers:
        headers.update(extra_headers)
    request = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        data = response.read(MAX_BYTES)
        charset = response.headers.get_content_charset() or "utf-8"
        return data.decode(charset, "replace")


async def fetch_text(
    url: str,
    *,
    timeout: float = 15,
    retries: int = 1,
    headers: dict | None = None,
) -> str:
    last_error: Exception | None = None
    for attempt in range(retries + 1):
        try:
            return await asyncio.to_thread(_fetch_sync, url, timeout, headers)
        except Exception as exc:
            last_error = exc
            log.warning("fetch failed (%s/%s) %s: %s", attempt + 1, retries + 1, url, exc)
            if attempt < retries:
                await asyncio.sleep(1 << attempt)
    raise FetchError(f"{url}: {last_error}")
