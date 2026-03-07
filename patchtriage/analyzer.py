"""Change analysis and interestingness ranking for matched function pairs."""

from __future__ import annotations


def _set_diff(a: list | set, b: list | set) -> tuple[list, list]:
    """Return (added, removed) between two collections."""
    sa, sb = set(a), set(b)
    return sorted(sb - sa), sorted(sa - sb)


def _call_names(func: dict, external_only: bool = False) -> set[str]:
    out = set()
    for c in func.get("called_functions", []):
        if external_only and not c.get("is_external"):
            continue
        out.add(c["name"])
    return out


def analyze_match(func_a: dict, func_b: dict) -> dict:
    """Compute change signals between a matched pair of functions."""

    signals = {}

    # Size delta
    signals["size_a"] = func_a.get("size", 0)
    signals["size_b"] = func_b.get("size", 0)
    signals["size_delta"] = signals["size_b"] - signals["size_a"]
    signals["size_delta_pct"] = (
        round(signals["size_delta"] / signals["size_a"] * 100, 1)
        if signals["size_a"] > 0 else 0
    )

    # Block count delta
    signals["blocks_a"] = func_a.get("block_count", 0)
    signals["blocks_b"] = func_b.get("block_count", 0)
    signals["blocks_delta"] = signals["blocks_b"] - signals["blocks_a"]

    # Instruction count delta
    signals["instr_a"] = func_a.get("instr_count", 0)
    signals["instr_b"] = func_b.get("instr_count", 0)
    signals["instr_delta"] = signals["instr_b"] - signals["instr_a"]

    # String changes
    str_a = set(func_a.get("strings", []))
    str_b = set(func_b.get("strings", []))
    signals["strings_added"] = sorted(str_b - str_a)
    signals["strings_removed"] = sorted(str_a - str_b)

    # External call changes
    ext_a = _call_names(func_a, external_only=True)
    ext_b = _call_names(func_b, external_only=True)
    signals["ext_calls_added"] = sorted(ext_b - ext_a)
    signals["ext_calls_removed"] = sorted(ext_a - ext_b)

    # All call changes
    calls_a = _call_names(func_a)
    calls_b = _call_names(func_b)
    signals["calls_added"] = sorted(calls_b - calls_a)
    signals["calls_removed"] = sorted(calls_a - calls_b)

    # Constant changes
    const_a = set(func_a.get("constants", []))
    const_b = set(func_b.get("constants", []))
    signals["constants_added"] = sorted(const_b - const_a)
    signals["constants_removed"] = sorted(const_a - const_b)

    # Mnemonic histogram delta (compare/branch density)
    hist_a = func_a.get("mnemonic_hist", {})
    hist_b = func_b.get("mnemonic_hist", {})

    branch_mnemonics = {"je", "jne", "jz", "jnz", "jg", "jge", "jl", "jle",
                        "ja", "jae", "jb", "jbe", "jmp", "call",
                        "b.eq", "b.ne", "b.gt", "b.lt", "b.ge", "b.le",
                        "cbz", "cbnz", "tbz", "tbnz", "bl", "b"}
    cmp_mnemonics = {"cmp", "test", "cmn", "tst"}

    branch_a = sum(hist_a.get(m, 0) for m in branch_mnemonics)
    branch_b = sum(hist_b.get(m, 0) for m in branch_mnemonics)
    signals["branch_delta"] = branch_b - branch_a

    cmp_a = sum(hist_a.get(m, 0) for m in cmp_mnemonics)
    cmp_b = sum(hist_b.get(m, 0) for m in cmp_mnemonics)
    signals["compare_delta"] = cmp_b - cmp_a

    return signals


def compute_interestingness(signals: dict) -> float:
    """Compute a heuristic interestingness score from change signals.

    Higher = more likely to be a meaningful/security-relevant change.
    """
    score = 0.0

    # New external calls are very interesting
    score += len(signals.get("ext_calls_added", [])) * 3.0
    score += len(signals.get("ext_calls_removed", [])) * 2.0

    # New internal calls
    score += len(signals.get("calls_added", [])) * 1.0
    score += len(signals.get("calls_removed", [])) * 0.5

    # String changes often indicate new error paths or feature changes
    score += len(signals.get("strings_added", [])) * 1.5
    score += len(signals.get("strings_removed", [])) * 0.5

    # Size changes
    abs_delta = abs(signals.get("size_delta", 0))
    if abs_delta > 100:
        score += 2.0
    elif abs_delta > 20:
        score += 1.0

    # Block changes (new control flow)
    blocks_delta = abs(signals.get("blocks_delta", 0))
    score += blocks_delta * 0.8

    # New comparisons/branches = new checks
    score += max(0, signals.get("compare_delta", 0)) * 1.2
    score += max(0, signals.get("branch_delta", 0)) * 0.6

    # New constants
    score += len(signals.get("constants_added", [])) * 0.3

    return round(score, 2)


def analyze_diff(features_a: dict, features_b: dict, match_data: dict) -> dict:
    """Analyze all matched functions and produce ranked change data."""
    # Build lookup by entry address
    idx_a = {f["entry"]: f for f in features_a["functions"]}
    idx_b = {f["entry"]: f for f in features_b["functions"]}
    # Also build by name for fallback
    name_a = {f["name"]: f for f in features_a["functions"]}
    name_b = {f["name"]: f for f in features_b["functions"]}

    analyzed = []
    for m in match_data["matches"]:
        fa = idx_a.get(m["entry_a"]) or name_a.get(m["name_a"])
        fb = idx_b.get(m["entry_b"]) or name_b.get(m["name_b"])
        if not fa or not fb:
            continue

        signals = analyze_match(fa, fb)
        interest = compute_interestingness(signals)

        analyzed.append({
            "name_a": m["name_a"],
            "name_b": m["name_b"],
            "entry_a": m["entry_a"],
            "entry_b": m["entry_b"],
            "match_score": m["score"],
            "match_method": m["method"],
            "uncertain": m.get("uncertain", False),
            "interestingness": interest,
            "signals": signals,
        })

    # Sort by interestingness descending
    analyzed.sort(key=lambda x: x["interestingness"], reverse=True)

    return {
        "binary_a": match_data.get("binary_a", "A"),
        "binary_b": match_data.get("binary_b", "B"),
        "total_matches": len(analyzed),
        "unmatched_a": match_data.get("unmatched_a", []),
        "unmatched_b": match_data.get("unmatched_b", []),
        "functions": analyzed,
    }
