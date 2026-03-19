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

STACK_PROTECTION_FUNCS = {"__stack_chk_fail", "__stack_chk_guard", "__fortify_fail",
                          "stack_chk_fail", "stack_chk_guard", "fortify_fail"}

BOUNDS_CONSTANTS = {
    0x10, 0x20, 0x40, 0x80, 0x100, 0x200, 0x400, 0x800,
    0x1000, 0x2000, 0x4000, 0xFFFF, 0xFFFFFFFF,
}

ERROR_KEYWORDS = {"error", "fail", "invalid", "overflow", "underflow", "denied",
                  "refused", "corrupt", "abort", "panic", "out of bounds",
                  "buffer", "null", "bad", "illegal", "exceed", "limit"}
VALIDATION_STRING_CATEGORIES = {"error", "bounds", "path", "http"}

TRIAGE_PRIORITY = {
    "security_fix_likely": 0,
    "security_fix_possible": 1,
    "behavior_change": 2,
    "unknown": 3,
    "refactor": 4,
    "unchanged": 5,
}


def _normalize_symbol(name: str) -> str:
    """Normalize a symbol name: strip leading underscores and __chk/__s suffixes."""
    # Strip Mach-O leading underscore
    n = name.lstrip("_")
    # Strip compiler-fortified suffixes: ___sprintf_chk -> sprintf
    for suffix in ("_chk", "_s"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    return n


def _normalize_set(names: set[str]) -> dict[str, str]:
    """Return {normalized_name: original_name} for a set of symbol names."""
    return {_normalize_symbol(n): n for n in names}


ROLE_HINTS: dict[str, tuple[str, ...]] = {
    "parser": ("parse", "decode", "read_", "load_", "lex", "scan"),
    "validator": ("valid", "check", "verify", "guard", "sanitize", "bounds"),
    "codec": ("compress", "decompress", "encode", "decode", "zstd", "huf", "fse"),
    "benchmark": ("bench", "bmk", "lorem", "datagen"),
}


def _context_roles(func_diff: dict) -> set[str]:
    """Use recorded roles when present and fall back to name-based hints."""
    roles = set(func_diff.get("roles_a", [])) | set(func_diff.get("roles_b", []))
    if roles:
        return roles

    hinted = set()
    for key in ("name_a", "name_b"):
        name = _normalize_symbol(str(func_diff.get(key, "")))
        for role, markers in ROLE_HINTS.items():
            if any(marker in name for marker in markers):
                hinted.add(role)
    return hinted


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
    api_families_added = set(signals.get("api_families_added", []))
    string_categories_added = set(signals.get("string_categories_added", []))
    roles = _context_roles(func_diff)

    security_semantic_evidence = any([
        signals.get("strings_added"),
        signals.get("strings_removed"),
        signals.get("ext_calls_added"),
        signals.get("ext_calls_removed"),
        signals.get("api_families_added"),
        signals.get("api_families_removed"),
        signals.get("string_categories_added"),
        signals.get("string_categories_removed"),
    ])
    semantic_evidence = any([
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
    security_context = bool(
        security_semantic_evidence
        or {"parser", "validator"} & roles
        or "validation" in api_families_added
        or {"error", "bounds", "path", "http"} & string_categories_added
    )
    algorithmic_context = bool({"codec", "benchmark"} & roles) and not security_context

    # Build normalized lookup for symbol matching across platforms
    norm_added = _normalize_set(ext_added | calls_added)
    norm_removed = _normalize_set(ext_removed)

    # --- Heuristic 1: unsafe -> safer API swap ---
    for unsafe, safer_list in UNSAFE_API_SWAPS.items():
        if unsafe in norm_removed:
            orig_unsafe = norm_removed[unsafe]
            for safer in safer_list:
                if safer in norm_added:
                    orig_safer = norm_added[safer]
                    rationale.append(f"Replaced unsafe `{orig_unsafe}` with `{orig_safer}`")
                    sec_score += 3.0
                    break
            else:
                rationale.append(f"Removed call to unsafe `{orig_unsafe}`")
                sec_score += 1.5

    # --- Heuristic 2: stack protection added ---
    for pf in STACK_PROTECTION_FUNCS:
        if pf in norm_added and not algorithmic_context:
            rationale.append(f"Added stack protection (`{pf}`)")
            sec_score += 2.5

    # --- Heuristic 3: new bounds-like constants + new checks ---
    bounds_added = consts_added & BOUNDS_CONSTANTS
    if bounds_added and signals.get("compare_delta", 0) > 0 and security_context:
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

    if "validation" in api_families_added:
        rationale.append("Added calls in validation-oriented API family")
        sec_score += 1.0

    if {"error", "bounds"} & string_categories_added:
        rationale.append(
            f"New string categories suggest validation/bounds handling: {sorted({'error', 'bounds'} & string_categories_added)}"
        )
        sec_score += 1.0

    if (
        signals.get("compare_delta", 0) > 0
        and signals.get("branch_delta", 0) > 0
        and security_context
        and (
            VALIDATION_STRING_CATEGORIES & string_categories_added
            or "validation" in api_families_added
            or error_strings
        )
    ):
        rationale.append(
            "Added checks and control-flow consistent with new input-validation or guard logic"
        )
        sec_score += 1.5

    if (
        signals.get("blocks_delta", 0) > 0
        and signals.get("instr_delta", 0) > 0
        and signals.get("compare_delta", 0) > 0
        and abs(signals.get("size_delta_pct", 0)) >= 5
        and security_context
    ):
        rationale.append("Control-flow and comparison growth suggests new guard or parser logic")
        sec_score += 0.75

    # --- Heuristic 5: new error-return paths (block growth + compare growth) ---
    if (signals.get("blocks_delta", 0) > 2
            and signals.get("compare_delta", 0) > 0
            and signals.get("branch_delta", 0) > 0
            and security_context):
        rationale.append(
            f"Added {signals['blocks_delta']} blocks, "
            f"{signals['compare_delta']} cmp(s), "
            f"{signals['branch_delta']} branch(es) — possible new validation paths"
        )
        sec_score += 1.5

    # --- Heuristic 6: large refactoring (size change with no security signals) ---
    abs_pct = abs(signals.get("size_delta_pct", 0))
    has_behavioral_signal = any([
        signals.get("strings_added"),
        signals.get("strings_removed"),
        signals.get("ext_calls_added"),
        signals.get("ext_calls_removed"),
        signals.get("calls_added"),
        signals.get("calls_removed"),
        signals.get("blocks_delta", 0),
        signals.get("instr_delta", 0),
        signals.get("branch_delta", 0),
        signals.get("compare_delta", 0),
    ])
    size_pct = abs(signals.get("size_delta_pct", 0))
    block_delta = abs(signals.get("blocks_delta", 0))
    instr_delta = abs(signals.get("instr_delta", 0))
    branch_positive = signals.get("branch_delta", 0) > 0
    structure_only_modest = (
        not semantic_evidence
        and not branch_positive
        and size_pct < 15
        and block_delta <= 4
        and instr_delta <= 25
    )
    structure_only_large = (
        not semantic_evidence
        and size_pct >= 15
    )
    synthetic_scope = any(
        str(func_diff.get(key, "")).startswith(("section:", "imports:", "__binary__"))
        for key in ("name_a", "name_b")
    )

    # --- Determine label ---
    if sec_score >= 4.0:
        label = "security_fix_likely"
    elif sec_score >= 2.0:
        label = "security_fix_possible"
    elif sec_score >= 0.5:
        label = "behavior_change"
    elif structure_only_modest:
        label = "unchanged"
        rationale.append("Primarily structural churn without semantic evidence")
    elif structure_only_large:
        label = "refactor"
        rationale.append("Large structural change without semantic evidence")
    elif func_diff.get("interestingness", 0) < 0.5:
        label = "unchanged"
    elif abs_pct > 20 and not rationale:
        label = "refactor"
        rationale.append(f"Large size change ({signals.get('size_delta_pct', 0)}%) without clear security signals")
    elif has_behavioral_signal and func_diff.get("interestingness", 0) >= 2.0:
        label = "behavior_change"
        rationale.append("Meaningful structural or call-flow change without direct security evidence")
    elif synthetic_scope and has_behavioral_signal and func_diff.get("interestingness", 0) >= 1.0:
        label = "behavior_change"
        rationale.append("Coarse binary-region or import-surface change worth manual review")
    elif synthetic_scope and abs_pct > 0:
        label = "refactor"
        rationale.append("Coarse binary-region size change without direct security evidence")
    elif synthetic_scope and func_diff.get("interestingness", 0) >= 1.0:
        label = "behavior_change"
        rationale.append("Coarse binary-region change surfaced by fallback analysis")
    elif func_diff.get("interestingness", 0) < 2.0:
        label = "unchanged"
    else:
        label = "unknown"

    if label == "behavior_change" and roles and roles <= {"formatter", "logger"} and not sec_score:
        if not semantic_evidence or set(signals.get("string_categories_added", [])) <= {"format"}:
            label = "unchanged" if abs_pct < 15 else "refactor"
            rationale = ["Formatter/logging-oriented churn without security evidence"]
    if label.startswith("security_fix") and algorithmic_context and not security_context:
        label = "behavior_change" if abs_pct < 20 else "refactor"
        rationale = ["Algorithmic/codec change with structural growth but no direct security evidence"]

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

    diff_data["functions"].sort(
        key=lambda func: (
            TRIAGE_PRIORITY.get(func.get("triage_label", "unknown"), 99),
            -func.get("interestingness", 0),
        )
    )

    return diff_data
