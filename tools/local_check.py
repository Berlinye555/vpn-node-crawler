"""在本地网络里验证节点是否真的能用。

GitHub Actions 跑在境外，只能回答「节点后端是否活着」；跑在境内就过不了墙的
明文节点，在那边同样是「可用」。这个脚本在本机跑，测的是「节点在这里能不能用」。

用法：
    python tools/local_check.py --clash output/clash.yaml --mihomo ./mihomo.exe
    python tools/local_check.py --sub https://example.com/sub --limit 100
    python tools/local_check.py --clash output/clash.yaml --protocols vless,trojan

需要 mihomo 内核：https://github.com/MetaCubeX/mihomo/releases
也可以用 MIHOMO_PATH 环境变量指定。
"""

from __future__ import annotations

import argparse
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vpnnode.models import Node  # noqa: E402
from vpnnode.parsers.clash import parse_clash_yaml  # noqa: E402
from vpnnode.renderers.clash import _to_clash  # noqa: E402
from vpnnode.sources.common import parse_any_text  # noqa: E402

BASE_PORT = 25000
MIXED_PORT = 27890
API_PORT = 29090


def find_mihomo(explicit: str) -> str | None:
    if explicit:
        return explicit if pathlib.Path(explicit).exists() else None
    for name in ("mihomo.exe", "mihomo"):
        local = ROOT / name
        if local.exists():
            return str(local)
        found = shutil.which(name)
        if found:
            return found
    env = os.environ.get("MIHOMO_PATH", "")
    return env if env and pathlib.Path(env).exists() else None


def load_nodes(clash: str, sub: str) -> list[Node]:
    if clash:
        text = pathlib.Path(clash).read_text(encoding="utf-8", errors="replace")
    elif sub:
        request = urllib.request.Request(sub, headers={"User-Agent": "local-check"})
        with urllib.request.urlopen(request, timeout=30) as response:
            text = response.read(8 * 1024 * 1024).decode("utf-8", "replace")
    else:
        raise SystemExit("需要 --clash 或 --sub 指定节点来源")
    if "proxies:" in text:
        return parse_clash_yaml(text)
    return parse_any_text(text)


def build_config(nodes: list[Node]) -> dict:
    proxies = []
    listeners = []
    for index, node in enumerate(nodes):
        name = f"n{index:05d}"
        proxies.append(_to_clash(node, name))
        listeners.append({
            "name": f"l{index:05d}", "type": "mixed", "port": BASE_PORT + index,
            "listen": "127.0.0.1", "proxy": name,
        })
    return {
        "mixed-port": MIXED_PORT,
        "external-controller": f"127.0.0.1:{API_PORT}",
        "mode": "rule",
        "log-level": "silent",
        "proxies": proxies,
        "proxy-groups": [],
        "rules": ["MATCH,DIRECT"],
        "listeners": listeners,
    }


def _get(url: str, proxy: str, timeout: float) -> tuple[int, int]:
    """返回 (状态码, 耗时毫秒)；失败状态码为 0。proxy 为空时走真实直连（绕过系统代理）。"""
    if proxy:
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy, "https": proxy}))
    else:
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    request = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    started = time.monotonic()
    try:
        with opener.open(request, timeout=timeout) as response:
            response.read(2048)
            return response.status, int((time.monotonic() - started) * 1000)
    except urllib.error.HTTPError as exc:
        return exc.code, int((time.monotonic() - started) * 1000)
    except Exception:
        return 0, 0


def _wait_api(proc, timeout: float = 30) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            return False
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{API_PORT}/version", timeout=1) as r:
                if r.status == 200:
                    return True
        except Exception:
            pass
        time.sleep(0.2)
    return False


def check_batch(
    nodes: list[Node],
    mihomo: str,
    url: str,
    timeout: float,
    concurrency: int,
) -> dict[str, tuple[bool, int]]:
    workdir = tempfile.mkdtemp(prefix="local-check-")
    config_path = pathlib.Path(workdir) / "config.yaml"
    config_path.write_text(
        yaml.safe_dump(build_config(nodes), allow_unicode=True, sort_keys=False),
        encoding="utf-8")
    log_path = pathlib.Path(workdir) / "mihomo.log"
    with open(log_path, "wb") as handle:
        proc = subprocess.Popen(
            [mihomo, "-f", str(config_path), "-d", workdir],
            stdout=handle, stderr=handle,
        )

    try:
        if not _wait_api(proc):
            tail = ""
            try:
                tail = log_path.read_text(encoding="utf-8", errors="replace")[-500:]
            except Exception:
                pass
            print(f"  ! 内核未能启动（exit={proc.returncode}）：{tail.strip()[:300]}")
            return {}

        results: dict[str, tuple[bool, int]] = {}

        def one(index: int, node: Node) -> None:
            code, delay = _get(url, f"http://127.0.0.1:{BASE_PORT + index}", timeout)
            results[node.fingerprint] = (code != 0, delay)

        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            list(executor.map(lambda pair: one(*pair), enumerate(nodes)))
        return results
    finally:
        try:
            proc.terminate()
            proc.wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="在本地网络验证节点可用性")
    parser.add_argument("--clash", default="", help="本地 Clash 配置文件")
    parser.add_argument("--sub", default="", help="订阅地址（base64 / Clash / 明文均可）")
    parser.add_argument("--mihomo", default="", help="mihomo 内核路径")
    parser.add_argument("--url", default="https://www.google.com/generate_204",
                        help="测试目标（默认 google，境内需过墙；gstatic 国内可直连，不适合当判据）")
    parser.add_argument("--timeout", type=float, default=5.0, help="单个节点超时秒数")
    parser.add_argument("--concurrency", type=int, default=30, help="并发数")
    parser.add_argument("--batch", type=int, default=60, help="每批节点数")
    parser.add_argument("--limit", type=int, default=0, help="只测前 N 个节点")
    parser.add_argument("--protocols", default="", help="只测指定协议，逗号分隔，如 vless,trojan")
    parser.add_argument("--show-ok", action="store_true", help="列出全部可用节点")
    args = parser.parse_args(argv)

    mihomo = find_mihomo(args.mihomo)
    if not mihomo:
        print("未找到 mihomo 内核。请从 https://github.com/MetaCubeX/mihomo/releases 下载，")
        print("放到项目根目录并用 --mihomo 指定，或设置 MIHOMO_PATH 环境变量。")
        return 2

    nodes = load_nodes(args.clash, args.sub)
    if args.protocols:
        wanted = {p.strip().lower() for p in args.protocols.split(",") if p.strip()}
        nodes = [n for n in nodes if n.protocol in wanted]
    if args.limit:
        nodes = nodes[:args.limit]
    if not nodes:
        print("没有可测试的节点。")
        return 1

    print(f"mihomo : {mihomo}")
    print(f"目标   : {args.url}  (超时 {args.timeout}s, 并发 {args.concurrency})")
    print(f"节点   : {len(nodes)} 个，分 {((len(nodes) - 1) // args.batch) + 1} 批")

    direct, _ = _get(args.url, "", min(args.timeout, 5))
    if direct:
        print(f"[自检] 本机直连目标：{direct}（可直连，结果会偏乐观，换一个墙外目标更准）")
    else:
        print("[自检] 本机直连目标：超时（正常，目标在墙外，下面全部经节点测试）")
    print()

    started = time.monotonic()
    ok: dict[str, int] = {}
    batches = [nodes[i:i + args.batch] for i in range(0, len(nodes), args.batch)]
    for index, batch in enumerate(batches, 1):
        print(f"[{index}/{len(batches)}] 测试 {len(batch)} 个节点...", end=" ", flush=True)
        results = check_batch(batch, mihomo, args.url, args.timeout, args.concurrency)
        good = 0
        for node in batch:
            passed, delay = results.get(node.fingerprint, (False, 0))
            if passed:
                ok[node.fingerprint] = delay
                good += 1
        print(f"可用 {good}")

    elapsed = time.monotonic() - started
    by_protocol: dict[str, list[int]] = {}
    for node in nodes:
        stats = by_protocol.setdefault(node.protocol, [0, 0])
        stats[1] += 1
        if node.fingerprint in ok:
            stats[0] += 1

    print(f"\n=== 结果（{elapsed:.0f}s）===")
    print(f"可用 {len(ok)} / {len(nodes)}  ({len(ok) * 100 // max(1, len(nodes))}%)")
    for protocol, (good, total) in sorted(by_protocol.items(), key=lambda x: -x[1][0]):
        print(f"  {protocol:9} {good:3}/{total:3}")

    if ok:
        ranked = sorted(
            ((node, ok[node.fingerprint]) for node in nodes if node.fingerprint in ok),
            key=lambda item: item[1])
        print("\n可用节点（按延迟）：")
        for node, delay in ranked[:30]:
            print(f"  {delay:5}ms  {node.protocol:8} {node.server}:{node.port}")
        if len(ranked) > 30 and not args.show_ok:
            print(f"  ... 其余 {len(ranked) - 30} 个略（--show-ok 全部列出）")
    else:
        print("\n没有任何节点可用。若全部协议均为 0，先确认本机能直连目标站点。")

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
