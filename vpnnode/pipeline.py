from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import pathlib
import sys
import time
from collections import Counter
from datetime import datetime, timezone

import yaml

from vpnnode.aggregator import aggregate
from vpnnode.deliver import upload_outputs
from vpnnode.filters.ai_probe import HAS_CURL_CFFI, check_ai, overall_level
from vpnnode.filters.alive import check_alive, filter_alive
from vpnnode.filters.exit_probe import probe_exits
from vpnnode.filters.intel import apply_intel
from vpnnode.filters.precheck import precheck
from vpnnode.filters.probe import ProbeResult, probe_nodes
from vpnnode.filters.quality import apply_quality
from vpnnode.filters.reputation import apply_reputation
from vpnnode.history import append_history, render_markdown
from vpnnode.models import Node
from vpnnode.renderers.base64_sub import render_base64
from vpnnode.renderers.clash import country_label, render_clash
from vpnnode.sources import github, subscription, telegram, webpage
from vpnnode.sources.common import parse_any_text

log = logging.getLogger(__name__)

DEFAULT_FILTERS = {
    "tls_policy": "strict",
    "probe_concurrency": 30,
    "probe_timeout_s": 5,
    "tcp_fail_threshold": 2,
    "max_handshake_ms": 3000,
    "max_nodes_total": 300,
    "max_nodes_per_group": 30,
    "dnsbl_zones": ["zen.spamhaus.org"],
    "reputation_enabled": True,
}

class InsufficientNodes(Exception):
    """最终节点数低于 min_nodes，不应覆盖已有订阅。"""


class UploadFailed(Exception):
    """上传到 Worker 连续失败。"""


FETCHERS = {
    "github": github.fetch_source,
    "webpage": webpage.fetch_source,
    "subscription": subscription.fetch_source,
    "telegram": telegram.fetch_source,
}


def load_yaml(path: pathlib.Path, default):
    if not path.exists():
        return default
    with path.open(encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return data if data is not None else default


def offline_load(directory: pathlib.Path) -> list[Node]:
    nodes: list[Node] = []
    for file in sorted(directory.iterdir()):
        if not file.is_file():
            continue
        text = file.read_text(encoding="utf-8", errors="replace")
        batch = parse_any_text(text)
        for node in batch:
            node.source = f"offline:{file.name}"
        nodes.extend(batch)
        log.info("offline %s -> %d nodes", file.name, len(batch))
    return nodes


async def fetch_all(specs: list[dict]) -> tuple[list[Node], list[dict]]:
    async def one(spec: dict):
        fetcher = FETCHERS.get(spec.get("type", ""))
        if fetcher is None:
            return spec, [], f"unknown source type: {spec.get('type')}"
        try:
            return spec, await fetcher(spec), ""
        except Exception as exc:
            log.error("source error %s: %s", spec, exc)
            return spec, [], str(exc)

    results = await asyncio.gather(*(one(spec) for spec in specs))
    nodes: list[Node] = []
    failed: list[dict] = []
    for spec, batch, error in results:
        if error or not batch:
            failed.append({"spec": spec, "error": error or "empty result"})
            continue
        nodes.extend(batch)
    return nodes, failed


def _sample_rejections(rejected: list[tuple[Node, str]], limit: int = 200) -> list[dict]:
    samples = []
    for node, reason in rejected[:limit]:
        samples.append({
            "name": node.name,
            "protocol": node.protocol,
            "server": node.server,
            "port": node.port,
            "reason": reason,
            "source": node.source,
        })
    return samples


def _reason_counts(rejected: list[tuple[Node, str]]) -> dict:
    return dict(Counter(reason for _, reason in rejected))


def _short_source(source: str) -> str:
    return source.split(":", 1)[-1][:90] if ":" in source else source


def _source_stats(report: dict) -> dict:
    fetched = report["stats"].get("fetched_by_source", {})
    final = report["stats"].get("final_by_source", {})
    return {
        name: {"fetched": fetched.get(name, 0), "final": final.get(name, 0)}
        for name in set(fetched) | set(final)
    }


def assign_display_names(nodes: list[Node]) -> None:
    """统一命名：{国旗} {地区} {序号}，序号按探测延迟升序（quality 已排序）。"""
    counters: dict[str, int] = {}
    for node in nodes:
        label = country_label(str(node.params.get("country") or ""))
        counters[label] = counters.get(label, 0) + 1
        suffix = "".join(f" {tag}" for tag in node.params.get("tags") or [])
        node.name = f"{label} {counters[label]:02d}{suffix}"


def export_nodes(nodes: list[Node]) -> list[dict]:
    """单节点明细，给自检和后续分析用；clash/base64 订阅只放渲染后的配置。"""
    rows = []
    for node in nodes:
        p = node.params
        rows.append({
            "name": node.name,
            "protocol": node.protocol,
            "server": node.server,
            "port": node.port,
            "source": _short_source(node.source),
            "exit_ip": p.get("exit_ip", ""),
            "exit_country": p.get("exit_country", ""),
            "country": p.get("country", ""),
            "asn": p.get("asn", ""),
            "ip_type": p.get("ip_type", ""),
            "proxy": bool(p.get("proxy")),
            "hosting": bool(p.get("hosting")),
            "dnsbl": bool(p.get("dnsbl_hit")),
            "self_signed": bool(p.get("self_signed")),
            "latency_ms": p.get("latency_ms"),
            "latency_level": p.get("latency_level", ""),
            "safety": p.get("safety", ""),
            "ip_score": p.get("ip_score", 0),
            "tags": p.get("tags", []),
        })
    return rows


async def run_pipeline(args: argparse.Namespace) -> dict:
    config_dir = pathlib.Path(args.config)
    output_dir = pathlib.Path(args.out)
    output_dir.mkdir(parents=True, exist_ok=True)

    filters = {**DEFAULT_FILTERS, **(load_yaml(config_dir / "filters.yaml", {}) or {})}
    report: dict = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "offline" if args.offline else "online",
        "stats": {},
        "failed_sources": [],
        "rejected_samples": [],
    }
    all_rejected: list[tuple[Node, str]] = []

    stage_start = time.monotonic()
    timings: dict[str, float] = {}

    def mark(name: str) -> None:
        nonlocal stage_start
        now = time.monotonic()
        timings[name] = round(now - stage_start, 1)
        log.info("stage %-12s %6.1fs", name, now - stage_start)
        stage_start = now

    if args.offline:
        nodes = offline_load(pathlib.Path(args.offline))
        report["stats"]["fetched"] = {"total": len(nodes), "by_source": {}}
    else:
        specs = (load_yaml(config_dir / "sources.yaml", {}) or {}).get("sources", [])
        nodes, failed = await fetch_all(specs)
        report["failed_sources"] = failed
        report["stats"]["fetched"] = {
            "total": len(nodes),
            "specs": len(specs),
            "urls": sum(len(spec.get("urls", [])) for spec in specs),
        }
        log.info("fetched %d nodes from %d source entries", len(nodes), len(specs))

    report["stats"]["fetched_by_source"] = {
        _short_source(source): count
        for source, count in Counter(node.source for node in nodes).most_common()
    }
    mark("fetch")

    nodes, aggregate_stats = aggregate(nodes)
    report["stats"]["aggregate"] = aggregate_stats
    mark("aggregate")

    nodes, rejected = precheck(nodes, filters)
    all_rejected.extend(rejected)
    report["stats"]["precheck"] = {"kept": len(nodes), "rejected": len(rejected),
                                   "reasons": _reason_counts(rejected)}
    mark("precheck")

    if args.no_probe:
        results = {node.fingerprint: ProbeResult(ok=True, handshake_ms=0) for node in nodes}
        report["stats"]["probe"] = {"skipped": True}
    else:
        results = await probe_nodes(nodes, filters)
        report["stats"]["probe"] = {
            "probed": len(results),
            "failed": sum(1 for r in results.values() if not r.ok),
            "bad_cert": sum(1 for r in results.values() if r.tls_ok is False),
            "ws_dead": sum(1 for r in results.values() if r.ws_ok is False),
        }

    mark("probe")

    if args.no_reputation:
        report["stats"]["reputation"] = {"skipped": True}
    else:
        nodes, rep_rejected, rep_stats = await apply_reputation(nodes, filters)
        all_rejected.extend(rep_rejected)
        report["stats"]["reputation"] = rep_stats
    mark("reputation")

    mihomo_path = getattr(args, "mihomo", "") or os.environ.get("MIHOMO_PATH", "")
    alive_results: dict = {}
    if mihomo_path:
        alive_input = len(nodes)
        alive_results = await check_alive(nodes, mihomo_path, filters)
        if alive_results:
            min_rate = float(filters.get("alive_min_success_rate", 0.66))
            nodes, alive_rejected = filter_alive(nodes, alive_results, min_rate)
            all_rejected.extend(alive_rejected)
            for node in nodes:
                result = alive_results.get(node.fingerprint)
                if result is not None and result.delay:
                    node.params["latency_ms"] = result.delay
            report["stats"]["alive"] = {
                "input": alive_input,
                "tested": len(alive_results),
                "reliable": sum(1 for r in alive_results.values() if r.rate >= min_rate),
                "dead": sum(1 for r in alive_results.values() if r.success == 0),
                "unstable": sum(1 for r in alive_results.values() if 0 < r.rate < min_rate),
                "samples": int(filters.get("alive_samples", 3)),
            }
        else:
            report["stats"]["alive"] = {"skipped": True}
    else:
        report["stats"]["alive"] = {"skipped": "no mihomo"}
    mark("alive")

    # 出口探测只对 alive 确认可靠的节点做：未测到的节点出口未知，不值得占端口
    if mihomo_path and filters.get("exit_probe", True):
        probe_min_rate = float(filters.get("alive_min_success_rate", 0.66))
        probe_targets = [
            node for node in nodes
            if (alive_results.get(node.fingerprint) is not None
                and alive_results[node.fingerprint].rate >= probe_min_rate)
        ]
        exit_infos = await probe_exits(probe_targets, mihomo_path, filters) if probe_targets else {}
        for node in nodes:
            info = exit_infos.get(node.fingerprint)
            if not info:
                continue
            node.params["exit_ip"] = info["ip"]
            node.params["exit_loc"] = info["loc"]
            if info["warp"]:
                node.params["warp"] = info["warp"]
        report["stats"]["exit_probe"] = {"tested": len(probe_targets), "resolved": len(exit_infos)}
    else:
        report["stats"]["exit_probe"] = {"skipped": True}
    mark("exit")

    kept, quality_rejected = apply_quality(nodes, results, filters)
    all_rejected.extend(quality_rejected)
    report["stats"]["quality"] = {"kept": len(kept), "rejected": len(quality_rejected),
                                  "reasons": _reason_counts(quality_rejected)}
    mark("quality")

    if mihomo_path and filters.get("ai_probe_enabled", True) and kept:
        ai_results = await check_ai(kept, mihomo_path, filters)
        for node in kept:
            levels = ai_results.get(node.fingerprint)
            if not levels:
                continue
            node.params["ai"] = levels
            node.params["ai_level"] = overall_level(levels)
        ai_levels = Counter(node.params.get("ai_level") for node in kept if node.params.get("ai_level"))
        by_target: dict[str, Counter] = {}
        for levels in ai_results.values():
            for target, level in levels.items():
                by_target.setdefault(target, Counter())[level] += 1
        report["stats"]["ai"] = {
            "tested": len(ai_results),
            "levels": dict(ai_levels),
            "by_target": {name: dict(counter) for name, counter in by_target.items()},
            "impersonate": HAS_CURL_CFFI,
        }
    else:
        report["stats"]["ai"] = {"skipped": True}
    mark("ai")

    if filters.get("intel_enabled", True) and kept:
        report["stats"]["tagging"] = await apply_intel(kept, filters)
    else:
        report["stats"]["tagging"] = {"skipped": True}
    mark("intel")

    assign_display_names(kept)
    report["stats"]["final"] = len(kept)
    report["stats"]["final_by_source"] = {
        _short_source(source): count
        for source, count in Counter(node.source for node in kept).most_common()
    }
    report["stats"]["timings"] = timings
    report["rejected_samples"] = _sample_rejections(all_rejected)

    min_nodes = int(getattr(args, "min_nodes", 0) or 0)
    if len(kept) < min_nodes:
        raise InsufficientNodes(f"final node count {len(kept)} < min_nodes {min_nodes}")

    (output_dir / "clash.yaml").write_text(render_clash(kept, filters), encoding="utf-8")
    (output_dir / "sub.base64").write_text(render_base64(kept), encoding="utf-8")
    (output_dir / "nodes.json").write_text(
        json.dumps(export_nodes(kept), ensure_ascii=False, indent=2), encoding="utf-8"
    )
    (output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    record = {
        "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "generated_at": report["generated_at"],
        "fetched": report["stats"]["fetched"].get("total", 0),
        "precheck": report["stats"]["precheck"].get("kept", 0),
        "ws_dead": report["stats"]["probe"].get("ws_dead", 0),
        "alive_reliable": report["stats"]["alive"].get("reliable", 0),
        "alive_dead": report["stats"]["alive"].get("dead", 0),
        "final": len(kept),
        "total_seconds": round(sum(timings.values()), 1),
        "timings": timings,
        "sources": _source_stats(report),
    }
    records = append_history(output_dir / "history.jsonl", record)
    (output_dir / "history.md").write_text(render_markdown(records), encoding="utf-8")

    if not getattr(args, "no_upload", False):
        uploaded = upload_outputs(output_dir)
        if uploaded is False:
            uploaded = upload_outputs(output_dir)  # 失败重试一次
        if uploaded is False:
            raise UploadFailed("worker upload failed after retry")

    log.info("done: %d nodes -> %s", len(kept), output_dir)
    print(json.dumps(report["stats"], ensure_ascii=False, indent=2))
    return report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vpnnode", description="VPN 节点抓取与安全过滤")
    parser.add_argument("--config", default="config", help="配置目录")
    parser.add_argument("--out", default="output", help="输出目录")
    parser.add_argument("--offline", default="", help="离线模式：解析该目录下的样本文件")
    parser.add_argument("--no-probe", action="store_true", help="跳过连通性探测")
    parser.add_argument("--no-reputation", action="store_true", help="跳过 IP 信誉检测")
    parser.add_argument("--no-upload", action="store_true", help="跳过上传到 Worker")
    parser.add_argument("--mihomo", default="", help="mihomo 内核路径；提供后对每个节点做真实连通测试")
    parser.add_argument("--min-nodes", type=int, default=20, help="最终节点数低于该值时任务失败")
    parser.add_argument("--verbose", action="store_true", help="输出调试日志")
    return parser


def main(argv: list[str] | None = None) -> None:
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    try:
        asyncio.run(run_pipeline(args))
    except (InsufficientNodes, UploadFailed) as exc:
        log.error("%s; previous subscription kept", exc)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
