"""Colorized terminal output for PatchTriage reports."""

from __future__ import annotations

import sys
import textwrap

from .report import collapse_low_information_families

# ── ANSI color codes ──────────────────────────────────────────────────────────

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
ITALIC = "\033[3m"
UNDERLINE = "\033[4m"

# Foreground
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"
WHITE = "\033[37m"
GRAY = "\033[90m"

# Bright
BRED = "\033[91m"
BGREEN = "\033[92m"
BYELLOW = "\033[93m"
BBLUE = "\033[94m"
BMAGENTA = "\033[95m"
BCYAN = "\033[96m"

# Background
BG_RED = "\033[41m"
BG_YELLOW = "\033[43m"
BG_BLUE = "\033[44m"
BG_GRAY = "\033[100m"


def _no_color() -> bool:
    return not sys.stdout.isatty() or "NO_COLOR" in __import__("os").environ


def _c(code: str, text: str) -> str:
    if _no_color():
        return text
    return f"{code}{text}{RESET}"


# ── Label formatting ──────────────────────────────────────────────────────────

def label_color(label: str) -> str:
    colors = {
        "security_fix_likely": f"{BOLD}{BG_RED}{WHITE}",
        "security_fix_possible": f"{BOLD}{YELLOW}",
        "behavior_change": f"{BOLD}{BLUE}",
        "refactor": f"{DIM}{WHITE}",
        "unchanged": f"{DIM}{GRAY}",
        "unknown": f"{DIM}{GRAY}",
    }
    tag = {
        "security_fix_likely": " SEC-LIKELY ",
        "security_fix_possible": " SEC-POSSIBLE ",
        "behavior_change": " BEHAVIOR ",
        "refactor": " REFACTOR ",
        "unchanged": " UNCHANGED ",
        "unknown": " UNKNOWN ",
    }
    return _c(colors.get(label, ""), tag.get(label, f" {label.upper()} "))


def severity_color(severity: str | None) -> str:
    if not severity:
        return ""
    colors = {
        "critical": f"{BOLD}{BG_RED}{WHITE}",
        "high": f"{BOLD}{RED}",
        "medium": f"{BOLD}{YELLOW}",
        "low": f"{BLUE}",
        "info": f"{DIM}{GRAY}",
    }
    return _c(colors.get(severity, ""), f" {severity.upper()} ")


# ── Pretty print helpers ─────────────────────────────────────────────────────

def header(text: str):
    width = min(80, len(text) + 4)
    print()
    print(_c(BOLD + CYAN, "=" * width))
    print(_c(BOLD + CYAN, f"  {text}"))
    print(_c(BOLD + CYAN, "=" * width))


def subheader(text: str):
    print()
    print(_c(BOLD + BBLUE, f"── {text} ──"))


def kv(key: str, value, indent: int = 2):
    prefix = " " * indent
    print(f"{prefix}{_c(DIM, key + ':')} {value}")


def delta_color(val: int | float, suffix: str = "") -> str:
    if val > 0:
        return _c(GREEN, f"+{val}{suffix}")
    elif val < 0:
        return _c(RED, f"{val}{suffix}")
    return _c(GRAY, f"{val}{suffix}")


def bar(value: float, max_val: float, width: int = 20) -> str:
    if max_val <= 0:
        return ""
    filled = int(value / max_val * width)
    filled = min(filled, width)
    return _c(YELLOW, "#" * filled) + _c(GRAY, "-" * (width - filled))


def _shorten(text: str, limit: int = 88) -> str:
    text = text.replace("\n", "\\n")
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _preview_strings(strings: list[str], color: str, prefix: str):
    if not strings:
        return
    rendered = [_c(color, repr(_shorten(s))) for s in strings[:3]]
    more = f" {_c(DIM, f'(+{len(strings)-3} more)')}" if len(strings) > 3 else ""
    print(f"     {prefix} {', '.join(rendered)}{more}")


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


# ── Main report printer ──────────────────────────────────────────────────────

def print_report(diff_data: dict, top_n: int = 30):
    """Print colorized report to terminal."""

    header("PatchTriage Security Patch Triage Report")
    print()
    kv("Binary A", _c(CYAN, diff_data.get("binary_a", "N/A")), indent=0)
    kv("Binary B", _c(CYAN, diff_data.get("binary_b", "N/A")), indent=0)
    kv("Question", "Which changed functions deserve immediate RE attention?", indent=0)

    total = diff_data.get("total_matches", 0)
    ua = len(diff_data.get("unmatched_a", []))
    ub = len(diff_data.get("unmatched_b", []))
    print()
    kv("Matched", f"{_c(BOLD, str(total))} functions", indent=0)
    kv("Unmatched in A", _c(RED, str(ua)) if ua else "0", indent=0)
    kv("Unmatched in B", _c(GREEN, str(ub)) if ub else "0", indent=0)

    # Triage breakdown
    triage_sum = diff_data.get("triage_summary", {})
    if triage_sum:
        subheader("Triage Breakdown")
        for label in ["security_fix_likely", "security_fix_possible", "behavior_change",
                       "refactor", "unchanged", "unknown"]:
            count = triage_sum.get(label, 0)
            if count:
                print(f"  {label_color(label)} {_c(BOLD, str(count))}")

    # Executive summary
    exec_summary = diff_data.get("executive_summary")
    if exec_summary:
        subheader("Executive Summary (LLM)")
        for line in exec_summary.strip().split("\n"):
            print(f"  {_c(DIM, line)}")

    # Top changed functions
    funcs = diff_data.get("functions", [])
    interesting = [f for f in funcs if f.get("interestingness", 0) > 0]
    display_funcs, collapsed_summary = collapse_low_information_families(interesting)
    max_interest = max((f.get("interestingness", 0) for f in display_funcs), default=1)

    if collapsed_summary:
        subheader("Collapsed Families")
        for item in collapsed_summary[:8]:
            print(
                f"  {_c(DIM, item['representative'])} "
                f"represents {_c(BOLD, str(item['count']))} similar {label_color(item['label'])} changes"
            )

    subheader(f"Top {min(top_n, len(display_funcs))} Changed Functions")

    for i, func in enumerate(display_funcs[:top_n]):
        label = func.get("triage_label", "unknown")
        signals = func.get("signals", {})
        interest = func.get("interestingness", 0)

        print()
        # Function header line
        rank = _c(DIM, f"#{i+1}")
        name = _c(BOLD + WHITE, func["name_a"])
        lbl = label_color(label)
        interest_bar = bar(interest, max_interest, width=15)
        print(f"  {rank} {name} {lbl} {interest_bar} {_c(DIM, f'score={interest}')}")

        if func["name_a"] != func["name_b"]:
            print(f"     {_c(DIM, 'matched to')} {_c(CYAN, func['name_b'])}")
        if func.get("collapsed_similar_count"):
            print(
                f"     {_c(DIM, 'collapsed similar changes:')} "
                f"{_c(BOLD, str(func['collapsed_similar_count']))}"
            )

        # LLM vuln classification
        if func.get("llm_vuln_class"):
            sev = severity_color(func.get("llm_severity"))
            vuln = _c(BOLD + RED, func["llm_vuln_class"])
            vuln_name = _c(WHITE, func.get("llm_vuln_name", ""))
            conf = _c(DIM, f"({func.get('llm_fix_confidence', '?')})")
            print(f"     {sev} {vuln} {vuln_name} {conf}")
            if func.get("llm_attack_surface"):
                print(f"     {_c(DIM + ITALIC, 'Attack: ' + func['llm_attack_surface'])}")

        # LLM summary
        if func.get("llm_summary") and not func["llm_summary"].startswith("LLM error"):
            summary = func["llm_summary"]
            # Word wrap at ~76 chars
            wrapped = textwrap.fill(summary, width=74, initial_indent="     ",
                                    subsequent_indent="     ")
            print(_c(ITALIC, wrapped))
            if func.get("llm_category") and func["llm_category"] != "unknown":
                print(f"     {_c(DIM, 'Category:')} {_c(MAGENTA, func['llm_category'])}")

        # Size / blocks / instructions
        sd = signals.get("size_delta", 0)
        sd_pct = signals.get("size_delta_pct", 0)
        bd = signals.get("blocks_delta", 0)
        id_ = signals.get("instr_delta", 0)
        print(f"     {_c(DIM, 'Size:')} {signals.get('size_a', '?')} -> {signals.get('size_b', '?')} ({delta_color(sd_pct, '%')})"
              f"  {_c(DIM, 'Blocks:')} {delta_color(bd)}  {_c(DIM, 'Instrs:')} {delta_color(id_)}")

        # Heuristic rationale
        rationale = func.get("triage_rationale", [])
        if rationale and rationale != ["No strong signals detected"]:
            for r in rationale:
                wrapped = textwrap.fill(r, width=74, initial_indent="       ", subsequent_indent="       ")
                print(f"     {_c(YELLOW, '-')}{wrapped[6:]}")
        else:
            for note in _review_signals(signals):
                print(f"     {_c(YELLOW, '-')} {note}")

        # Call / string changes (compact)
        ext_added = signals.get("ext_calls_added", [])
        ext_removed = signals.get("ext_calls_removed", [])
        if ext_added:
            print(f"     {_c(GREEN, '+ calls:')} {', '.join(_c(GREEN, c) for c in ext_added)}")
        if ext_removed:
            print(f"     {_c(RED, '- calls:')} {', '.join(_c(RED, c) for c in ext_removed)}")
        str_added = signals.get("strings_added", [])
        str_removed = signals.get("strings_removed", [])
        if str_added:
            _preview_strings(str_added, GREEN, _c(GREEN, "+ strings:"))
        if str_removed:
            _preview_strings(str_removed, RED, _c(RED, "- strings:"))
        api_added = signals.get("api_families_added", [])
        if api_added:
            print(f"     {_c(GREEN, '+ api families:')} {', '.join(_c(GREEN, c) for c in api_added)}")
        cat_added = signals.get("string_categories_added", [])
        if cat_added:
            print(f"     {_c(GREEN, '+ string categories:')} {', '.join(_c(GREEN, c) for c in cat_added)}")

        # Separator
        print(f"  {_c(DIM, '─' * 70)}")

    # Unmatched functions
    unmatched_a = diff_data.get("unmatched_a", [])
    unmatched_b = diff_data.get("unmatched_b", [])
    if unmatched_a or unmatched_b:
        subheader("Unmatched Functions")
        if unmatched_b:
            print(f"  {_c(BOLD + GREEN, f'New in B ({len(unmatched_b)}):')}")
            for name in unmatched_b[:20]:
                print(f"    {_c(GREEN, '+')} {_c(CYAN, name)}")
        if unmatched_a:
            print(f"  {_c(BOLD + RED, f'Removed from A ({len(unmatched_a)}):')}")
            for name in unmatched_a[:20]:
                print(f"    {_c(RED, '-')} {_c(CYAN, name)}")

    print()
