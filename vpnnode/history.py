from __future__ import annotations

import json
import pathlib

MAX_RECORDS = 180


def load_history(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    records: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return records[-MAX_RECORDS:]


def append_history(path: pathlib.Path, record: dict) -> list[dict]:
    records = load_history(path)
    records.append(record)
    records = records[-MAX_RECORDS:]
    path.write_text(
        "\n".join(json.dumps(item, ensure_ascii=False) for item in records) + "\n",
        encoding="utf-8",
    )
    return records


def render_markdown(records: list[dict], days: int = 14) -> str:
    recent = [item for item in records if item.get("date")][-days:]
    lines = [
        "# 节点质量趋势",
        "",
        f"最近 {len(recent)} 次运行。由流水线自动生成，勿手工编辑。",
        "",
        "| 日期 | 抓取 | 安全过滤 | WS 死 | 真实可用 | 最终 | 耗时 |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    for item in recent:
        lines.append(
            "| {date} | {fetched} | {precheck} | {ws_dead} | {alive} | {final} | {seconds}s |".format(
                date=item.get("date", "-"),
                fetched=item.get("fetched", 0),
                precheck=item.get("precheck", 0),
                ws_dead=item.get("ws_dead", 0),
                alive=item.get("alive_reliable", 0),
                final=item.get("final", 0),
                seconds=item.get("total_seconds", "-"),
            )
        )

    last = recent[-1] if recent else None
    if last and last.get("sources"):
        lines += [
            "",
            "## 最近一次各源贡献",
            "",
            "| 源 | 抓取 | 最终 | 存活率 |",
            "| --- | --- | --- | --- |",
        ]
        for name, stats in sorted(last["sources"].items(),
                                  key=lambda pair: -pair[1].get("final", 0)):
            fetched = stats.get("fetched", 0)
            final = stats.get("final", 0)
            rate = f"{final / fetched * 100:.0f}%" if fetched else "-"
            lines.append(f"| {name} | {fetched} | {final} | {rate} |")
    return "\n".join(lines) + "\n"
