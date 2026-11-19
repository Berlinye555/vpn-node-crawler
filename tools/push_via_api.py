"""通过 GitHub API 推送当前工作区到远端分支。

本机 git push 受网络限制不可用时使用。每次基于远端 HEAD 生成一个新提交，
文件集合取自 `git ls-files`，不依赖本地提交历史。

用法：
    python tools/push_via_api.py
    GITHUB_REPO=owner/name GITHUB_BRANCH=main python tools/push_via_api.py
"""

from __future__ import annotations

import base64
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = os.environ.get("GITHUB_REPO", "Berlinye555/vpn-node-crawler")
BRANCH = os.environ.get("GITHUB_BRANCH", "main")
API = f"https://api.github.com/repos/{REPO}"
COMMIT_MESSAGE = "chore: sync workspace"


def get_token() -> str:
    out = subprocess.run(
        ["git", "credential", "fill"],
        input="protocol=https\nhost=github.com\n\n",
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    for line in out.strip().splitlines():
        if line.startswith("password="):
            return line.split("=", 1)[1]
    raise SystemExit("no github credential found in git credential manager")


def call(token: str, method: str, url: str, payload=None, retries: int = 4, allow_404: bool = False):
    for attempt in range(retries):
        try:
            data = json.dumps(payload).encode() if payload is not None else None
            request = urllib.request.Request(
                url,
                data=data,
                method=method,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "User-Agent": "vpn-crawler-push",
                    "Content-Type": "application/json",
                },
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                body = response.read().decode()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as exc:
            if allow_404 and exc.code == 404:
                return None
            raise RuntimeError(f"HTTP {exc.code}: {exc.read().decode()[:300]}") from exc
        except Exception:
            if attempt == retries - 1:
                raise
            time.sleep(2)


def main() -> None:
    token = get_token()
    head = call(token, "GET", f"{API}/git/ref/heads/{BRANCH}", allow_404=True)
    parents = [head["object"]["sha"]] if head else []
    # 以远端最新 tree 为基底，只覆盖本地提供的文件；CI 提交的 output/ 等远端文件不会被误删
    base_tree = None
    if head:
        commit_info = call(token, "GET", f"{API}/git/commits/{head['object']['sha']}")
        base_tree = commit_info["tree"]["sha"]

    files = sorted(
        path
        for path in subprocess.run(["git", "ls-files"], capture_output=True, text=True,
                                   check=True).stdout.replace("\r", "").split("\n")
        if path and pathlib.Path(path).is_file()
    )
    print(f"uploading {len(files)} files to {REPO}:{BRANCH}")

    tree_items = []
    for index, path in enumerate(files, 1):
        blob = call(token, "POST", f"{API}/git/blobs", {
            "content": base64.b64encode(pathlib.Path(path).read_bytes()).decode(),
            "encoding": "base64",
        })
        tree_items.append({"path": path, "mode": "100644", "type": "blob", "sha": blob["sha"]})
        if index % 15 == 0 or index == len(files):
            print(f"  {index}/{len(files)}")

    tree_payload = {"tree": tree_items}
    if base_tree:
        tree_payload["base_tree"] = base_tree
    tree = call(token, "POST", f"{API}/git/trees", tree_payload)
    commit_message = sys.argv[1] if len(sys.argv) > 1 else COMMIT_MESSAGE
    commit = call(token, "POST", f"{API}/git/commits", {
        "message": commit_message, "tree": tree["sha"], "parents": parents,
    })
    if head:
        call(token, "PATCH", f"{API}/git/refs/heads/{BRANCH}", {"sha": commit["sha"]})
    else:
        call(token, "POST", f"{API}/git/refs", {"ref": f"refs/heads/{BRANCH}", "sha": commit["sha"]})
    print(f"pushed {commit['sha'][:12]} -> {REPO}:{BRANCH}")


if __name__ == "__main__":
    main()
