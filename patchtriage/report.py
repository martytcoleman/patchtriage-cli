"""Generate Markdown (and optionally HTML) reports from diff data."""

from __future__ import annotations
import json
from datetime import datetime


def _label_badge(label: str) -> str:
    badges = {
        "security_fix_likely": "**[SEC-LIKELY]**",
        "security_fix_possible": "**[SEC-POSSIBLE]**",
        "behavior_change": "[BEHAVIOR]",
        "refactor": "[REFACTOR]",
        "unchanged": "[UNCHANGED]",
        "unknown": "[UNKNOWN]",
    }
    return badges.get(label, f"[{label.upper()}]")


def generate_markdown(diff_data: dict, top_n: int = 30) -> str:
    """Generate a Markdown report from triaged diff data."""
    lines: list[str] = []
    lines.append("# PatchTriage Diff Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Binary A:** `{diff_data.get('binary_a', 'N/A')}`")
    lines.append(f"**Binary B:** `{diff_data.get('binary_b', 'N/A')}`")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Matched functions | {diff_data.get('total_matches', 0)} |")
    lines.append(f"| Unmatched in A | {len(diff_data.get('unmatched_a', []))} |")
    lines.append(f"| Unmatched in B | {len(diff_data.get('unmatched_b', []))} |")
    lines.append("")

    # Triage summary
    triage_sum = diff_data.get("triage_summary", {})
    if triage_sum:
        lines.append("### Triage Breakdown")
        lines.append("")
        lines.append("| Label | Count |")
        lines.append("|-------|-------|")
        for label in ["security_fix_likely", "security_fix_possible", "behavior_change",
                       "refactor", "unchanged", "unknown"]:
            if label in triage_sum:
                lines.append(f"| {_label_badge(label)} | {triage_sum[label]} |")
        lines.append("")

    # Top changed functions
    funcs = diff_data.get("functions", [])
    # Filter out unchanged for the detail section
    interesting = [f for f in funcs if f.get("interestingness", 0) > 0]

    lines.append(f"## Top {min(top_n, len(interesting))} Changed Functions")
    lines.append("")

    for i, func in enumerate(interesting[:top_n]):
        label = func.get("triage_label", "unknown")
        badge = _label_badge(label)
        confidence = func.get("triage_confidence", 0)
        signals = func.get("signals", {})

        lines.append(f"### {i+1}. `{func['name_a']}` {badge}")
        if func["name_a"] != func["name_b"]:
            lines.append(f"  Matched to: `{func['name_b']}`")
        lines.append("")
        lines.append(f"- **Interestingness:** {func.get('interestingness', 0)}")
        lines.append(f"- **Match score:** {func.get('match_score', 0)} ({func.get('match_method', '')})")
        if func.get("uncertain"):
            lines.append(f"- **Match uncertain** (close alternatives exist)")
        lines.append(f"- **Triage confidence:** {confidence}")
        lines.append(f"- **Size:** {signals.get('size_a', '?')} -> {signals.get('size_b', '?')} ({signals.get('size_delta_pct', 0):+.1f}%)")
        lines.append(f"- **Blocks:** {signals.get('blocks_a', '?')} -> {signals.get('blocks_b', '?')} ({signals.get('blocks_delta', 0):+d})")
        lines.append(f"- **Instructions:** {signals.get('instr_a', '?')} -> {signals.get('instr_b', '?')} ({signals.get('instr_delta', 0):+d})")
        lines.append("")

        # Rationale
        rationale = func.get("triage_rationale", [])
        if rationale and rationale != ["No strong signals detected"]:
            lines.append("**Rationale:**")
            for r in rationale:
                lines.append(f"- {r}")
            lines.append("")

        # Detail changes
        if signals.get("ext_calls_added"):
            lines.append(f"  Ext calls added: `{'`, `'.join(signals['ext_calls_added'])}`")
        if signals.get("ext_calls_removed"):
            lines.append(f"  Ext calls removed: `{'`, `'.join(signals['ext_calls_removed'])}`")
        if signals.get("strings_added"):
            lines.append(f"  Strings added: {signals['strings_added'][:10]}")
        if signals.get("strings_removed"):
            lines.append(f"  Strings removed: {signals['strings_removed'][:10]}")
        lines.append("")
        lines.append("---")
        lines.append("")

    # Unmatched functions
    unmatched_a = diff_data.get("unmatched_a", [])
    unmatched_b = diff_data.get("unmatched_b", [])
    if unmatched_a or unmatched_b:
        lines.append("## Unmatched Functions")
        lines.append("")
        if unmatched_b:
            lines.append(f"### New in B ({len(unmatched_b)})")
            for name in unmatched_b[:50]:
                lines.append(f"- `{name}`")
            lines.append("")
        if unmatched_a:
            lines.append(f"### Removed from A ({len(unmatched_a)})")
            for name in unmatched_a[:50]:
                lines.append(f"- `{name}`")
            lines.append("")

    return "\n".join(lines)


def generate_html(markdown_text: str) -> str:
    """Wrap markdown in a simple HTML page. Very basic — no markdown parser needed."""
    # Simple conversion: just wrap in <pre> with some styling
    escaped = markdown_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    return f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>PatchTriage Report</title>
<style>
body {{ font-family: 'Courier New', monospace; max-width: 900px; margin: 40px auto; padding: 0 20px; background: #1a1a2e; color: #e0e0e0; line-height: 1.6; }}
pre {{ white-space: pre-wrap; word-wrap: break-word; }}
</style>
</head>
<body>
<pre>{escaped}</pre>
</body>
</html>"""
