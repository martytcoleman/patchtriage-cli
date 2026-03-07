"""Security-focused patch triage heuristics."""

from __future__ import annotations

# Maps unsafe -> safer replacements
UNSAFE_API_SWAPS: dict[str, list[str]] = {
    "strcpy":   ["strncpy", "strlcpy", "snprintf", "memcpy_s"],
    "strcat":   ["strncat", "strlcat"],
    "sprintf":  ["snprintf", "sprintf_s"],
    "vsprintf": ["vsnprintf", "vsprintf_s"],
    "gets":     ["fgets", "gets_s"],
    "scanf":    ["sscanf", "fscanf"],  # loose, but directional
    "memcpy":   ["memcpy_s", "memmove_s"],
    "memmove":  ["memmove_s"],
}

STACK_PROTECTION_FUNCS = {"__stack_chk_fail", "__stack_chk_guard", "__fortify_fail"}

BOUNDS_CONSTANTS = {
    0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800,
    0x1000, 0x2000, 0x4000, 0xFFFF, 0xFFFFFFFF,
}

ERROR_KEYWORDS = {"error", "fail", "invalid", "overflow", "underflow", "denied",
                  "refused", "corrupt", "abort", "panic", "out of bounds",
                  "buffer", "null", "bad", "illegal", "exceed", "limit"}


def triage_function(func_diff: dict) -> dict:
    """Apply triage heuristics to a single function diff entry.

    Returns dict with triage_label, rationale (list of strings), confidence (0-1).
    """
    signals = func_diff.get("signals", {})
    rationale: list[str] = []
    sec_score = 0.0

    ext_added = set(signals.get("ext_calls_added", []))
    ext_removed = set(signals.get("ext_calls_removed", []))
    calls_added = set(signals.get("calls_added", []))
    strings_added = signals.get("strings_added", [])
    strings_removed = signals.get("strings_removed", [])
    consts_added = set(signals.get("constants_added", []))

    # --- Heuristic 1: unsafe -> safer API swap ---
    for unsafe, safer_list in UNSAFE_API_SWAPS.items():
        if unsafe in ext_removed:
            for safer in safer_list:
                if safer in ext_added:
                    rationale.append(f"Replaced unsafe `{unsafe}` with `{safer}`")
                    sec_score += 3.0
                    break
            else:
                # Removed unsafe without clear replacement
                rationale.append(f"Removed call to unsafe `{unsafe}`")
                sec_score += 1.5

    # --- Heuristic 2: stack protection added ---
    for pf in STACK_PROTECTION_FUNCS:
        if pf in calls_added:
            rationale.append(f"Added stack protection (`{pf}`)")
            sec_score += 2.5

    # --- Heuristic 3: new bounds-like constants + new checks ---
    bounds_added = consts_added & BOUNDS_CONSTANTS
    if bounds_added and signals.get("compare_delta", 0) > 0:
        rationale.append(
            f"Added bounds constant(s) {[hex(c) for c in sorted(bounds_added)]} "
            f"with {signals['compare_delta']} new comparison(s)"
        )
        sec_score += 2.0

    # --- Heuristic 4: new error strings ---
    error_strings = []
    for s in strings_added:
        sl = s.lower()
        if any(kw in sl for kw in ERROR_KEYWORDS):
            error_strings.append(s)
    if error_strings:
        rationale.append(f"Added error/validation string(s): {error_strings[:5]}")
        sec_score += 1.5 * min(len(error_strings), 3)

    # --- Heuristic 5: new error-return paths (block growth + compare growth) ---
    if (signals.get("blocks_delta", 0) > 2
            and signals.get("compare_delta", 0) > 0
            and signals.get("branch_delta", 0) > 0):
        rationale.append(
            f"Added {signals['blocks_delta']} blocks, "
            f"{signals['compare_delta']} cmp(s), "
            f"{signals['branch_delta']} branch(es) — possible new validation paths"
        )
        sec_score += 1.5

    # --- Heuristic 6: large refactoring (size change with no security signals) ---
    abs_pct = abs(signals.get("size_delta_pct", 0))

    # --- Determine label ---
    if sec_score >= 4.0:
        label = "security_fix_likely"
    elif sec_score >= 2.0:
        label = "security_fix_possible"
    elif sec_score >= 0.5:
        label = "behavior_change"
    elif func_diff.get("interestingness", 0) < 0.5:
        label = "unchanged"
    elif abs_pct > 30 and not rationale:
        label = "refactor"
        rationale.append(f"Large size change ({signals.get('size_delta_pct', 0)}%) without clear security signals")
    else:
        label = "unknown"

    confidence = min(sec_score / 8.0, 1.0)

    return {
        "triage_label": label,
        "rationale": rationale if rationale else ["No strong signals detected"],
        "confidence": round(confidence, 2),
    }


def triage_diff(diff_data: dict) -> dict:
    """Apply triage heuristics to all functions in a diff.

    Mutates diff_data in-place by adding triage info to each function entry.
    Also returns the modified diff_data.
    """
    for func in diff_data.get("functions", []):
        triage = triage_function(func)
        func["triage_label"] = triage["triage_label"]
        func["triage_rationale"] = triage["rationale"]
        func["triage_confidence"] = triage["confidence"]

    # Summary counts
    labels = {}
    for func in diff_data.get("functions", []):
        lbl = func.get("triage_label", "unknown")
        labels[lbl] = labels.get(lbl, 0) + 1
    diff_data["triage_summary"] = labels

    return diff_data
