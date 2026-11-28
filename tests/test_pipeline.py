import argparse
import asyncio
import base64
import json
import pathlib

import pytest
import yaml

from vpnnode.pipeline import run_pipeline

FIXTURES = pathlib.Path(__file__).parent / "fixtures"
CONFIG = pathlib.Path(__file__).parent.parent / "config"


def make_args(tmp_path, **overrides):
    defaults = dict(
        config=str(CONFIG),
        out=str(tmp_path / "out"),
        offline=str(FIXTURES),
        no_probe=True,
        no_reputation=True,
        no_upload=True,
        verbose=False,
    )
    defaults.update(overrides)
    return argparse.Namespace(**defaults)


def run_offline(tmp_path, **overrides):
    args = make_args(tmp_path, **overrides)
    return asyncio.run(run_pipeline(args))


def test_online_mode_requires_mihomo(tmp_path):
    """没有内核就跳过真实测试，会把从未验证的节点直接发布——必须拒绝。"""
    args = make_args(tmp_path, offline="", mihomo="")
    with pytest.raises(Exception) as exc:
        asyncio.run(run_pipeline(args))
    assert "mihomo" in str(exc.value)


def test_offline_pipeline_end_to_end(tmp_path):
    report = run_offline(tmp_path)
    out = tmp_path / "out"

    assert (out / "clash.yaml").exists()
    assert (out / "sub.base64").exists()
    assert (out / "report.json").exists()

    assert report["stats"]["final"] > 0
    assert report["stats"]["aggregate"]["unique"] > 0

    doc = yaml.safe_load((out / "clash.yaml").read_text(encoding="utf-8"))
    names = [p["name"] for p in doc["proxies"]]
    assert "EVIL-Script" not in names
    assert "Weak-SS" not in names
    assert "Plain-HTTP" not in names
    assert not any(p["server"] == "10.0.0.1" for p in doc["proxies"])
    assert any(p["server"] == "2.2.2.2" for p in doc["proxies"])


def test_offline_precheck_reasons_recorded(tmp_path):
    report = run_offline(tmp_path)
    reasons = report["stats"]["precheck"]["reasons"]
    assert reasons.get("private_address", 0) >= 1
    assert reasons.get("script_field", 0) >= 1
    assert reasons.get("unsupported_protocol", 0) >= 1
    assert reasons.get("weak_cipher", 0) >= 1
    assert reasons.get("insecure_tls", 0) >= 1


def test_offline_base64_subscription_decodes(tmp_path):
    run_offline(tmp_path)
    text = (tmp_path / "out" / "sub.base64").read_text(encoding="utf-8")
    lines = [l for l in base64.b64decode(text).decode().splitlines() if l.strip()]
    assert lines
    assert all("://" in line for line in lines)


def test_offline_dedup(tmp_path):
    report = run_offline(tmp_path)
    aggregate_stats = report["stats"]["aggregate"]
    assert aggregate_stats["duplicates"] >= 1


def test_nodes_are_renamed(tmp_path):
    run_offline(tmp_path)
    doc = yaml.safe_load((tmp_path / "out" / "clash.yaml").read_text(encoding="utf-8"))
    names = [p["name"] for p in doc["proxies"]]
    # 离线模式跳过信誉查询，没有国家信息，统一归入「其他」；名字后面可能跟分级标签
    assert names and all(name.startswith("🌍 其他 ") for name in names)
    nums = [int(name.split()[2]) for name in names]
    assert nums == list(range(1, len(names) + 1))


def test_report_json_written(tmp_path):
    run_offline(tmp_path)
    report = json.loads((tmp_path / "out" / "report.json").read_text(encoding="utf-8"))
    assert report["mode"] == "offline"
    assert "precheck" in report["stats"]
    assert isinstance(report["rejected_samples"], list)
