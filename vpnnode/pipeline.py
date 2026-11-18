from __future__ import annotations

import argparse
import asyncio
import json
import logging
import pathlib
import sys
from collections import Counter
from datetime import datetime, timezone

import yaml

from vpnnode.aggregator import aggregate
from vpnnode.deliver import upload_outputs
from vpnnode.filters.precheck import precheck
from vpnnode.filters.probe import ProbeResult, probe_nodes
from vpnnode.filters.quality import apply_quality
from vpnnode.filters.reputation import apply_reputation
from vpnnode.models import Node
from vpnnode.renderers.base64_sub import render_base64
from vpnnode.renderers.clash import render_clash
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

    nodes, aggregate_stats = aggregate(nodes)
    report["stats"]["aggregate"] = aggregate_stats

    nodes, rejected = precheck(nodes, filters)
    all_rejected.extend(rejected)
    report["stats"]["precheck"] = {"kept": len(nodes), "rejected": len(rejected),
                                   "reasons": _reason_counts(rejected)}

    if args.no_probe:
        results = {node.fingerprint: ProbeResult(ok=True, handshake_ms=0) for node in nodes}
        report["stats"]["probe"] = {"skipped": True}
    else:
        results = await probe_nodes(nodes, filters)
        report["stats"]["probe"] = {
            "probed": len(results),
            "failed": sum(1 for r in results.values() if not r.ok),
            "bad_cert": sum(1 for r in results.values() if r.tls_ok is False),
        }

    if args.no_reputation:
        report["stats"]["reputation"] = {"skipped": True}
    else:
        nodes, rep_rejected, rep_stats = await apply_reputation(nodes, filters)
        all_rejected.extend(rep_rejected)
        report["stats"]["reputation"] = rep_stats

    kept, quality_rejected = apply_quality(nodes, results, filters)
    all_rejected.extend(quality_rejected)
    report["stats"]["quality"] = {"kept": len(kept), "rejected": len(quality_rejected),
                                  "reasons": _reason_counts(quality_rejected)}
    report["stats"]["final"] = len(kept)
    report["rejected_samples"] = _sample_rejections(all_rejected)

    (output_dir / "clash.yaml").write_text(render_clash(kept, filters), encoding="utf-8")
    (output_dir / "sub.base64").write_text(render_base64(kept), encoding="utf-8")
    (output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8"
    )

    if not args.no_upload:
        upload_outputs(output_dir)

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
    report = asyncio.run(run_pipeline(args))
    final = report["stats"]["final"]
    if final < args.min_nodes:
        log.error("final node count %d < min_nodes %d, keeping previous subscription", final, args.min_nodes)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
