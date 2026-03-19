"""Tests for report rendering."""

from __future__ import annotations

import json
from pathlib import Path

from patchtriage.report import collapse_low_information_families, generate_html, generate_markdown


def test_markdown_report_includes_security_triage_framing():
    with open(Path("targets/open_source/diff_triaged.json")) as f:
        diff_data = json.load(f)

    markdown = generate_markdown(diff_data, top_n=3)

    assert "# PatchTriage Security Patch Triage Report" in markdown
    assert "Which changed functions deserve immediate reverse-engineering attention?" in markdown
    assert "_parse_http_request" in markdown
    assert "[SEC-LIKELY]" in markdown


def test_html_report_wraps_rendered_markdown():
    html = generate_html("# Title\n\n- item")
    assert "<h1>Title</h1>" in html
    assert "<li>item</li>" in html
    assert "<html" in html.lower()


def test_collapse_low_information_families_keeps_one_representative():
    funcs = [
        {
            "name_a": "FUN_A",
            "name_b": "FUN_B",
            "interestingness": 8.0,
            "triage_label": "behavior_change",
            "signals": {
                "string_categories_added": ["format"],
                "strings_added": ["%s (%s) and %s (%s) %s"],
                "calls_added": ["x", "y", "z", "w"],
                "calls_removed": ["a"],
            },
        },
        {
            "name_a": "FUN_C",
            "name_b": "FUN_D",
            "interestingness": 7.0,
            "triage_label": "behavior_change",
            "signals": {
                "string_categories_added": ["format"],
                "strings_added": ["%s (%s) and %s (%s) %s"],
                "calls_added": ["x", "y", "z", "w"],
                "calls_removed": ["a"],
            },
        },
    ]
    collapsed, summary = collapse_low_information_families(funcs)
    assert len(collapsed) == 1
    assert collapsed[0]["collapsed_similar_count"] == 1
    assert summary[0]["count"] == 2
