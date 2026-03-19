"""Change analysis and interestingness ranking for matched function pairs."""

from __future__ import annotations

from .features import enrich_feature_set
from .normalize import normalize_symbol


def _set_diff(a: list | set, b: list | set) -> tuple[list, list]:
    """Return (added, removed) between two collections."""
    sa, sb = set(a), set(b)
    return sorted(sb - sa), sorted(sa - sb)


def _call_names(func: dict, external_only: bool = False) -> set[str]:
    out = set()
    for c in func.get("called_functions", []):
        if external_only and not c.get("is_external"):
            continue
        name = c["name"]
        if not c.get("is_external") and _is_auto_name(name):
            continue
        out.add(name)
    return out


def _is_auto_name(name: str) -> bool:
    return (
        name.startswith("FUN_")
        or name.startswith("thunk_FUN_")
        or name.startswith("LAB_")
    )


def _set_change(a: list | set, b: list | set) -> tuple[list, list]:
    sa, sb = set(a), set(b)
    return sorted(sb - sa), sorted(sa - sb)


def _canonical_internal_calls(
    func: dict,
    side: str,
    map_entry_a_to_b: dict[str, str],
    map_entry_b_to_a: dict[str, str],
    map_a_to_b: dict[str, str],
    map_b_to_a: dict[str, str],
) -> set[str]:
    out = set()
    for c in func.get("called_functions", []):
        if c.get("is_external"):
            continue
        name = c["name"]
        entry = c.get("entry")
        if side == "a":
            matched = (map_entry_a_to_b.get(entry) if entry else None) or map_a_to_b.get(name)
            if matched:
                out.add(f"matched:{matched}")
            elif not _is_auto_name(name):
                out.add(f"named:{normalize_symbol(name)}")
        else:
            if entry and entry in map_entry_b_to_a:
                out.add(f"matched:{entry}")
            elif name in map_b_to_a:
                out.add(f"matched:{name}")
            elif not _is_auto_name(name):
                out.add(f"named:{normalize_symbol(name)}")
    return out


def analyze_match(func_a: dict, func_b: dict, *,
                  map_entry_a_to_b: dict[str, str] | None = None,
                  map_entry_b_to_a: dict[str, str] | None = None,
                  map_a_to_b: dict[str, str] | None = None,
                  map_b_to_a: dict[str, str] | None = None) -> dict:
    """Compute change signals between a matched pair of functions."""

    signals = {}
    map_entry_a_to_b = map_entry_a_to_b or {}
    map_entry_b_to_a = map_entry_b_to_a or {}
    map_a_to_b = map_a_to_b or {}
    map_b_to_a = map_b_to_a or {}

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

    # All call changes.
    # For internal calls, collapse matched callees onto a shared canonical id so
    # stripped binaries do not look wildly different just because auto-generated
    # FUN_<addr> names shifted between builds.
    calls_a = _call_names(func_a, external_only=True) | _canonical_internal_calls(
        func_a, "a", map_entry_a_to_b, map_entry_b_to_a, map_a_to_b, map_b_to_a,
    )
    calls_b = _call_names(func_b, external_only=True) | _canonical_internal_calls(
        func_b, "b", map_entry_a_to_b, map_entry_b_to_a, map_a_to_b, map_b_to_a,
    )
    signals["calls_added"] = sorted(calls_b - calls_a)
    signals["calls_removed"] = sorted(calls_a - calls_b)

    # Constant changes
    const_a = set(func_a.get("constants", []))
    const_b = set(func_b.get("constants", []))
    signals["constants_added"] = sorted(const_b - const_a)
    signals["constants_removed"] = sorted(const_a - const_b)
    signals["constant_buckets_added"], signals["constant_buckets_removed"] = _set_change(
        func_a.get("constant_buckets", []),
        func_b.get("constant_buckets", []),
    )

    signals["api_families_added"], signals["api_families_removed"] = _set_change(
        func_a.get("api_families", []),
        func_b.get("api_families", []),
    )
    signals["string_categories_added"], signals["string_categories_removed"] = _set_change(
        func_a.get("string_categories", []),
        func_b.get("string_categories", []),
    )

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
    score += len(signals.get("api_families_added", [])) * 1.0
    score += len(signals.get("string_categories_added", [])) * 0.8

    return round(score, 2)


def _adjust_interestingness(raw_score: float, func_a: dict, func_b: dict, signals: dict) -> float:
    """Downweight low-evidence anonymous churn that often dominates stripped binaries."""
    auto_named = _is_auto_name(func_a.get("name", "")) and _is_auto_name(func_b.get("name", ""))
    only_internal_churn = (
        signals.get("calls_added") or signals.get("calls_removed")
    ) and not any([
        signals.get("ext_calls_added"),
        signals.get("ext_calls_removed"),
        signals.get("strings_added"),
        signals.get("strings_removed"),
        signals.get("api_families_added"),
        signals.get("string_categories_added"),
        signals.get("compare_delta", 0) > 0,
        signals.get("branch_delta", 0) > 0,
        abs(signals.get("blocks_delta", 0)) > 2,
        abs(signals.get("instr_delta", 0)) > 20,
    ])
    if auto_named and only_internal_churn:
        return round(min(raw_score, 1.5), 2)
    roles_a = set(func_a.get("function_roles", []))
    roles_b = set(func_b.get("function_roles", []))
    roles = roles_a | roles_b
    format_only = roles and roles <= {"formatter", "logger"}
    semantic_evidence = any([
        signals.get("ext_calls_added"),
        signals.get("ext_calls_removed"),
        signals.get("api_families_added"),
        signals.get("string_categories_added"),
        signals.get("compare_delta", 0) > 0,
    ])
    if format_only and not semantic_evidence:
        return round(min(raw_score, 1.2), 2)
    return raw_score


def _repeat_structure_signature(signals: dict) -> tuple | None:
    """Return a coarse signature for repetitive low-information structural churn."""
    string_categories_added = set(signals.get("string_categories_added", []))
    strings_added = signals.get("strings_added", [])
    format_only_string = (
        len(strings_added) <= 1
        and string_categories_added <= {"format"}
    )
    has_semantic_evidence = any([
        signals.get("strings_added"),
        signals.get("strings_removed"),
        signals.get("ext_calls_added"),
        signals.get("ext_calls_removed"),
        signals.get("api_families_added"),
        signals.get("api_families_removed"),
        signals.get("string_categories_added"),
        signals.get("string_categories_removed"),
        signals.get("constants_added"),
        signals.get("constants_removed"),
        signals.get("constant_buckets_added"),
        signals.get("constant_buckets_removed"),
    ])
    if has_semantic_evidence and not format_only_string:
        return None
    if signals.get("compare_delta", 0) > 1:
        return None
    return (
        tuple(sorted(string_categories_added)),
        tuple(sorted(s[:32] for s in strings_added[:1])),
        round(signals.get("size_delta_pct", 0), 1),
        signals.get("blocks_delta", 0),
        signals.get("instr_delta", 0),
        signals.get("branch_delta", 0),
        signals.get("compare_delta", 0),
        len(signals.get("calls_added", [])),
        len(signals.get("calls_removed", [])),
    )


def _repeat_family_signature(signals: dict) -> tuple | None:
    """Return a broader family signature for repeated low-value change clusters."""
    if signals.get("ext_calls_added") or signals.get("ext_calls_removed"):
        return None
    if signals.get("api_families_added") or signals.get("api_families_removed"):
        return None
    if signals.get("constants_added") or signals.get("constants_removed"):
        return None
    if signals.get("constant_buckets_added") or signals.get("constant_buckets_removed"):
        return None
    cats = tuple(sorted(signals.get("string_categories_added", [])))
    if cats and set(cats) - {"format"}:
        return None
    strings = tuple(sorted(s[:48] for s in signals.get("strings_added", [])[:1]))
    return (
        cats,
        strings,
        len(signals.get("calls_added", [])),
        len(signals.get("calls_removed", [])),
    )


def analyze_diff(features_a: dict, features_b: dict, match_data: dict) -> dict:
    """Analyze all matched functions and produce ranked change data."""
    features_a = enrich_feature_set(features_a)
    features_b = enrich_feature_set(features_b)
    # Build lookup by entry address
    idx_a = {f["entry"]: f for f in features_a["functions"]}
    idx_b = {f["entry"]: f for f in features_b["functions"]}
    # Also build by name for fallback
    name_a = {f["name"]: f for f in features_a["functions"]}
    name_b = {f["name"]: f for f in features_b["functions"]}
    map_a_to_b = {m["name_a"]: m["name_b"] for m in match_data["matches"]}
    map_b_to_a = {m["name_b"]: m["name_a"] for m in match_data["matches"]}
    map_entry_a_to_b = {m["entry_a"]: m["entry_b"] for m in match_data["matches"]}
    map_entry_b_to_a = {m["entry_b"]: m["entry_a"] for m in match_data["matches"]}

    analyzed = []
    for m in match_data["matches"]:
        fa = idx_a.get(m["entry_a"]) or name_a.get(m["name_a"])
        fb = idx_b.get(m["entry_b"]) or name_b.get(m["name_b"])
        if not fa or not fb:
            continue

        signals = analyze_match(
            fa,
            fb,
            map_entry_a_to_b=map_entry_a_to_b,
            map_entry_b_to_a=map_entry_b_to_a,
            map_a_to_b=map_a_to_b,
            map_b_to_a=map_b_to_a,
        )
        interest = _adjust_interestingness(compute_interestingness(signals), fa, fb, signals)

        analyzed.append({
            "name_a": m["name_a"],
            "name_b": m["name_b"],
            "entry_a": m["entry_a"],
            "entry_b": m["entry_b"],
            "roles_a": fa.get("function_roles", []),
            "roles_b": fb.get("function_roles", []),
            "match_score": m["score"],
            "match_method": m["method"],
            "uncertain": m.get("uncertain", False),
            "interestingness": interest,
            "signals": signals,
        })

    signature_counts: dict[tuple, int] = {}
    family_counts: dict[tuple, int] = {}
    for item in analyzed:
        sig = _repeat_structure_signature(item["signals"])
        if sig is not None:
            signature_counts[sig] = signature_counts.get(sig, 0) + 1
        family_sig = _repeat_family_signature(item["signals"])
        if family_sig is not None:
            family_counts[family_sig] = family_counts.get(family_sig, 0) + 1

    for item in analyzed:
        sig = _repeat_structure_signature(item["signals"])
        if sig is None:
            count = 0
        else:
            count = signature_counts.get(sig, 0)
            if count >= 8:
                item["interestingness"] = min(item["interestingness"], 1.1)
            elif count >= 4:
                item["interestingness"] = min(item["interestingness"], 1.4)
            elif count == 3:
                item["interestingness"] = min(item["interestingness"], 2.2)
        family_sig = _repeat_family_signature(item["signals"])
        if family_sig is not None:
            family_count = family_counts.get(family_sig, 0)
            if family_count >= 6:
                item["interestingness"] = min(item["interestingness"], 1.6)
            elif family_count >= 4:
                item["interestingness"] = min(item["interestingness"], 2.0)

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
