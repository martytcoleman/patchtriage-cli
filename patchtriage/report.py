"""Generate Markdown (and optionally HTML) reports from diff data."""

from __future__ import annotations
from datetime import datetime


def collapse_low_information_families(funcs: list[dict]) -> tuple[list[dict], list[dict]]:
    """Keep one representative for repeated low-information families."""
    families: dict[tuple, list[dict]] = {}
    passthrough: list[dict] = []
    for func in funcs:
        sig = _collapse_signature(func)
        if sig is None:
            passthrough.append(func)
            continue
        families.setdefault(sig, []).append(func)

    collapsed = list(passthrough)
    summary = []
    for group in families.values():
        group.sort(key=lambda item: item.get("interestingness", 0), reverse=True)
        rep = dict(group[0])
        if len(group) > 1:
            rep["collapsed_similar_count"] = len(group) - 1
            rep["collapsed_similar_names"] = [item["name_a"] for item in group[1:6]]
            summary.append({
                "representative": rep["name_a"],
                "count": len(group),
                "label": rep.get("triage_label", "unknown"),
            })
        collapsed.append(rep)

    collapsed.sort(
        key=lambda func: (
            0 if func.get("triage_label", "").startswith("security_fix") else 1,
            -func.get("interestingness", 0),
        )
    )
    return collapsed, summary


def _collapse_signature(func: dict) -> tuple | None:
    label = func.get("triage_label", "unknown")
    if label.startswith("security_fix"):
        return None
    signals = func.get("signals", {})
    if signals.get("ext_calls_added") or signals.get("ext_calls_removed"):
        return None
    cats = tuple(sorted(signals.get("string_categories_added", [])))
    strings = tuple(sorted(_shorten(s, 48) for s in signals.get("strings_added", [])[:1]))
    if cats and set(cats) - {"format"}:
        return None
    if signals.get("api_families_added") or signals.get("api_families_removed"):
        return None
    if signals.get("constants_added") or signals.get("constants_removed"):
        return None
    return (
        label,
        cats,
        strings,
        len(signals.get("calls_added", [])),
        len(signals.get("calls_removed", [])),
    )


def _shorten(text: str, limit: int = 100) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _preview_list(values: list[str], limit: int = 3, text_limit: int = 80) -> str:
    preview = [_shorten(str(v), text_limit) for v in values[:limit]]
    suffix = f" (+{len(values) - limit} more)" if len(values) > limit else ""
    return ", ".join(repr(v) for v in preview) + suffix


def _review_signals(signals: dict) -> list[str]:
    notes = []
    if signals.get("ext_calls_added") or signals.get("ext_calls_removed"):
        notes.append(
            f"external calls +{len(signals.get('ext_calls_added', []))}/-{len(signals.get('ext_calls_removed', []))}"
        )
    if signals.get("compare_delta", 0) > 0 or signals.get("branch_delta", 0) > 0:
        notes.append(
            f"checks cmp {signals.get('compare_delta', 0):+d}, branch {signals.get('branch_delta', 0):+d}"
        )
    if signals.get("string_categories_added"):
        notes.append(f"string categories: {', '.join(signals['string_categories_added'][:3])}")
    elif signals.get("strings_added"):
        notes.append(f"strings added: {len(signals['strings_added'])}")
    if signals.get("blocks_delta", 0) or signals.get("instr_delta", 0):
        notes.append(
            f"structure blocks {signals.get('blocks_delta', 0):+d}, instr {signals.get('instr_delta', 0):+d}"
        )
    return notes[:4]


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


def _severity_badge(severity: str | None) -> str:
    if not severity:
        return ""
    badges = {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    }
    return badges.get(severity, severity.upper())


def generate_markdown(diff_data: dict, top_n: int = 30) -> str:
    """Generate a Markdown report from triaged diff data."""
    lines: list[str] = []
    lines.append("# PatchTriage Security Patch Triage Report")
    lines.append("")
    lines.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"**Binary A:** `{diff_data.get('binary_a', 'N/A')}`")
    lines.append(f"**Binary B:** `{diff_data.get('binary_b', 'N/A')}`")
    lines.append("**Primary question:** Which changed functions deserve immediate reverse-engineering attention?")
    lines.append("")

    # Executive summary (LLM-generated, if present)
    exec_summary = diff_data.get("executive_summary")
    if exec_summary:
        lines.append("## Executive Summary")
        lines.append("")
        lines.append(exec_summary)
        lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Metric | Value |")
    lines.append("|--------|-------|")
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
    interesting = [f for f in funcs if f.get("interestingness", 0) > 0]
    display_funcs, collapsed_summary = collapse_low_information_families(interesting)
    security_queue = [
        f for f in display_funcs
        if f.get("triage_label") in ("security_fix_likely", "security_fix_possible", "behavior_change")
    ]

    lines.append(f"## Security Review Queue")
    lines.append("")
    for i, func in enumerate(security_queue[: min(top_n, 10)], 1):
        lines.append(
            f"{i}. `{func['name_a']}` {_label_badge(func.get('triage_label', 'unknown'))} "
            f"(score {func.get('interestingness', 0)})"
        )
        if func.get("collapsed_similar_count"):
            lines.append(
                f"   Similar low-information changes collapsed: {func['collapsed_similar_count']}"
            )
    lines.append("")

    if collapsed_summary:
        lines.append("## Collapsed Families")
        lines.append("")
        for item in collapsed_summary[:10]:
            lines.append(
                f"- `{item['representative']}` represents {item['count']} similar `{item['label']}` changes"
            )
        lines.append("")

    lines.append(f"## Top {min(top_n, len(display_funcs))} Changed Functions")
    lines.append("")

    for i, func in enumerate(display_funcs[:top_n]):
        label = func.get("triage_label", "unknown")
        badge = _label_badge(label)
        confidence = func.get("triage_confidence", 0)
        signals = func.get("signals", {})

        lines.append(f"### {i+1}. `{func['name_a']}` {badge}")
        if func["name_a"] != func["name_b"]:
            lines.append(f"  Matched to: `{func['name_b']}`")
        lines.append("")
        if func.get("collapsed_similar_count"):
            lines.append(
                f"**Collapsed similar changes:** {func['collapsed_similar_count']}"
            )
            if func.get("collapsed_similar_names"):
                lines.append(
                    f"**Examples:** {', '.join(f'`{name}`' for name in func['collapsed_similar_names'])}"
                )
            lines.append("")

        # LLM vulnerability classification (if present)
        if func.get("llm_vuln_class"):
            sev = _severity_badge(func.get("llm_severity"))
            lines.append(f"> **{sev}** | **{func['llm_vuln_class']}** — {func.get('llm_vuln_name', 'Unknown')}")
            lines.append(f"> Fix confidence: {func.get('llm_fix_confidence', '?')}")
            if func.get("llm_attack_surface"):
                lines.append(f"> Attack surface: {func['llm_attack_surface']}")
            lines.append("")

        # LLM summary (if present)
        if func.get("llm_summary") and not func["llm_summary"].startswith("LLM error"):
            lines.append(f"**LLM Analysis:** {func['llm_summary']}")
            if func.get("llm_category") and func["llm_category"] != "unknown":
                lines.append(f"**Category:** {func['llm_category']}")
            lines.append("")

        lines.append(f"- **Interestingness:** {func.get('interestingness', 0)}")
        lines.append(f"- **Match score:** {func.get('match_score', 0)} ({func.get('match_method', '')})")
        if func.get("uncertain"):
            lines.append("- **Match uncertain** (close alternatives exist)")
        lines.append(f"- **Triage confidence:** {confidence}")
        roles = sorted(set(func.get("roles_a", [])) | set(func.get("roles_b", [])))
        if roles:
            lines.append(f"- **Inferred roles:** {', '.join(roles)}")
        lines.append(f"- **Size:** {signals.get('size_a', '?')} -> {signals.get('size_b', '?')} ({signals.get('size_delta_pct', 0):+.1f}%)")
        lines.append(f"- **Blocks:** {signals.get('blocks_a', '?')} -> {signals.get('blocks_b', '?')} ({signals.get('blocks_delta', 0):+d})")
        lines.append(f"- **Instructions:** {signals.get('instr_a', '?')} -> {signals.get('instr_b', '?')} ({signals.get('instr_delta', 0):+d})")
        lines.append("")

        # Heuristic rationale
        rationale = func.get("triage_rationale", [])
        if rationale and rationale != ["No strong signals detected"]:
            lines.append("**Heuristic Rationale:**")
            for r in rationale:
                lines.append(f"- {r}")
            lines.append("")
        else:
            notes = _review_signals(signals)
            if notes:
                lines.append("**Review Signals:**")
                for note in notes:
                    lines.append(f"- {note}")
                lines.append("")

        # Detail changes
        if signals.get("ext_calls_added"):
            lines.append(f"  Ext calls added: `{'`, `'.join(signals['ext_calls_added'])}`")
        if signals.get("ext_calls_removed"):
            lines.append(f"  Ext calls removed: `{'`, `'.join(signals['ext_calls_removed'])}`")
        if signals.get("strings_added"):
            lines.append(f"  Strings added: {_preview_list(signals['strings_added'], limit=4, text_limit=90)}")
        if signals.get("strings_removed"):
            lines.append(f"  Strings removed: {_preview_list(signals['strings_removed'], limit=3, text_limit=90)}")
        if signals.get("api_families_added"):
            lines.append(f"  API families added: {signals['api_families_added']}")
        if signals.get("string_categories_added"):
            lines.append(f"  String categories added: {signals['string_categories_added']}")
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
    """Wrap markdown in a styled HTML page."""
    escaped = markdown_text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

    # Minimal markdown -> HTML transforms for better rendering
    import re
    html = escaped
    # Headers
    html = re.sub(r"^### (.+)$", r"<h3>\1</h3>", html, flags=re.MULTILINE)
    html = re.sub(r"^## (.+)$", r"<h2>\1</h2>", html, flags=re.MULTILINE)
    html = re.sub(r"^# (.+)$", r"<h1>\1</h1>", html, flags=re.MULTILINE)
    # Bold
    html = re.sub(r"\*\*\[([^\]]+)\]\*\*", r'<span class="badge">\1</span>', html)
    html = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", html)
    # Inline code
    html = re.sub(r"`([^`]+)`", r"<code>\1</code>", html)
    # Blockquotes (LLM vuln classification)
    html = re.sub(r"^&gt; (.+)$", r'<div class="vuln-box">\1</div>', html, flags=re.MULTILINE)
    # Horizontal rules
    html = re.sub(r"^---$", "<hr>", html, flags=re.MULTILINE)
    # List items
    html = re.sub(r"^- (.+)$", r"<li>\1</li>", html, flags=re.MULTILINE)
    # Table rows (basic)
    html = re.sub(r"^\|(.+)\|$", lambda m: "<tr>" + "".join(
        f"<td>{c.strip()}</td>" for c in m.group(1).split("|")
    ) + "</tr>", html, flags=re.MULTILINE)
    html = re.sub(r"<tr><td>-+</td>.*?</tr>", "", html)  # remove separator rows
    # Paragraphs (double newlines)
    html = re.sub(r"\n\n", "</p><p>", html)
    html = re.sub(r"\n", "<br>\n", html)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PatchTriage Report</title>
<style>
:root {{
  --bg: #0d1117; --fg: #c9d1d9; --accent: #58a6ff; --border: #30363d;
  --sec-likely: #f85149; --sec-possible: #d29922; --behavior: #58a6ff;
  --refactor: #8b949e; --unchanged: #484f58;
  --severity-crit: #f85149; --severity-high: #db6d28;
  --severity-med: #d29922; --severity-low: #58a6ff;
}}
* {{ box-sizing: border-box; margin: 0; padding: 0; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif; background: var(--bg); color: var(--fg); max-width: 960px; margin: 0 auto; padding: 24px; line-height: 1.7; }}
h1 {{ color: #fff; border-bottom: 1px solid var(--border); padding-bottom: 12px; margin-bottom: 20px; font-size: 1.8em; }}
h2 {{ color: var(--accent); margin-top: 32px; margin-bottom: 12px; font-size: 1.4em; }}
h3 {{ color: #fff; margin-top: 20px; margin-bottom: 8px; font-size: 1.1em; }}
code {{ background: #161b22; padding: 2px 6px; border-radius: 4px; font-size: 0.9em; color: #79c0ff; }}
strong {{ color: #fff; }}
hr {{ border: none; border-top: 1px solid var(--border); margin: 20px 0; }}
li {{ margin-left: 20px; margin-bottom: 4px; }}
table {{ border-collapse: collapse; margin: 8px 0; }}
td {{ padding: 4px 12px; border: 1px solid var(--border); }}
tr:first-child td {{ font-weight: bold; background: #161b22; }}
.badge {{
  display: inline-block; padding: 2px 8px; border-radius: 12px; font-size: 0.85em; font-weight: 600;
}}
.badge:has(SEC-LIKELY), .badge:contains(SEC-LIKELY) {{ background: var(--sec-likely); color: #fff; }}
.vuln-box {{
  background: #161b22; border-left: 3px solid var(--sec-likely); padding: 8px 12px; margin: 8px 0; border-radius: 0 6px 6px 0;
}}
p {{ margin-bottom: 8px; }}
</style>
</head>
<body>
{html}
</body>
</html>"""
