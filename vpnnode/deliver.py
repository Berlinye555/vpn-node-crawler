from __future__ import annotations

import logging
import os
import pathlib
import urllib.request

log = logging.getLogger(__name__)

UPLOAD_FILES = ("clash.yaml", "sub.base64")  # report.json 不上传，避免通过订阅地址暴露


def upload_outputs(output_dir: pathlib.Path) -> bool:
    """把输出上传到 Cloudflare Worker；未配置环境变量时静默跳过。"""
    base_url = os.environ.get("WORKER_BASE_URL", "").rstrip("/")
    upload_token = os.environ.get("UPLOAD_TOKEN", "")
    access_key = os.environ.get("SUB_ACCESS_KEY", "")
    if not (base_url and upload_token and access_key):
        log.info("upload skipped: WORKER_BASE_URL / UPLOAD_TOKEN / SUB_ACCESS_KEY not set")
        return False

    for name in UPLOAD_FILES:
        path = output_dir / name
        if not path.exists():
            continue
        url = f"{base_url}/upload/{access_key}/{name}"
        request = urllib.request.Request(
            url,
            data=path.read_bytes(),
            headers={"Authorization": f"Bearer {upload_token}", "Content-Type": "text/plain"},
            method="PUT",
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                log.info("uploaded %s -> HTTP %s", name, response.status)
        except Exception as exc:
            log.error("upload failed for %s: %s", name, exc)
            return False
    return True
