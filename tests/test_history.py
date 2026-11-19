from vpnnode.history import append_history, load_history, render_markdown


def test_append_and_render(tmp_path):
    path = tmp_path / "history.jsonl"
    record = {
        "date": "2026-11-19",
        "fetched": 100,
        "precheck": 50,
        "ws_dead": 5,
        "alive_reliable": 20,
        "final": 18,
        "total_seconds": 120,
        "sources": {"src-a": {"fetched": 100, "final": 18}},
    }
    records = append_history(path, record)
    assert len(records) == 1
    assert load_history(path)[0]["fetched"] == 100

    markdown = render_markdown(load_history(path))
    assert "节点质量趋势" in markdown
    assert "| 2026-11-19 | 100 | 50 | 5 | 20 | 18 | 120s |" in markdown
    assert "| src-a | 100 | 18 | 18% |" in markdown


def test_load_skips_bad_lines(tmp_path):
    path = tmp_path / "history.jsonl"
    path.write_text('{"date": "2026-11-19", "final": 10}\nnot json\n', encoding="utf-8")
    records = load_history(path)
    assert len(records) == 1
    assert records[0]["final"] == 10


def test_render_handles_empty():
    markdown = render_markdown([])
    assert "节点质量趋势" in markdown
    assert "| 日期 |" in markdown
