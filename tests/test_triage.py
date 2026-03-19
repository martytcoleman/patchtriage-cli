"""Tests for triage heuristics."""

from patchtriage.analyzer import analyze_diff, analyze_match, compute_interestingness
from patchtriage.triage import triage_function


def test_unsafe_api_swap():
    func_diff = {
        "interestingness": 5.0,
        "signals": {
            "ext_calls_added": ["snprintf"],
            "ext_calls_removed": ["sprintf"],
            "calls_added": ["snprintf"],
            "calls_removed": ["sprintf"],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 5.0,
            "blocks_delta": 1,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("security_fix_likely", "security_fix_possible")
    assert any("sprintf" in r for r in result["rationale"])


def test_stack_protection_added():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": ["__stack_chk_fail"],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 2.0,
            "blocks_delta": 1,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert "security" in result["triage_label"]
    assert any("stack" in r.lower() for r in result["rationale"])


def test_no_signals_unchanged():
    func_diff = {
        "interestingness": 0.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 0,
            "blocks_delta": 0,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "unchanged"
    assert result["confidence"] == 0.0


def test_error_strings_detected():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["buffer overflow detected", "invalid input"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 10.0,
            "blocks_delta": 0,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert any("error" in r.lower() or "string" in r.lower() for r in result["rationale"])


def test_modest_internal_only_change_is_not_promoted_to_behavior():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": ["matched:FUN_2000"],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 10.0,
            "blocks_delta": 1,
            "instr_delta": 8,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "unchanged"


def test_non_security_change_with_semantic_string_signal_is_behavior():
    func_diff = {
        "interestingness": 3.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["%s (%s) and %s (%s) %s"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 10.0,
            "blocks_delta": 1,
            "instr_delta": 8,
            "compare_delta": 0,
            "branch_delta": 0,
            "string_categories_added": ["format"],
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "behavior_change"


def test_validation_style_growth_can_be_security_possible():
    func_diff = {
        "interestingness": 6.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["invalid path"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 12.0,
            "blocks_delta": 3,
            "instr_delta": 10,
            "compare_delta": 2,
            "branch_delta": 3,
            "api_families_added": ["validation"],
            "string_categories_added": ["error", "path"],
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("security_fix_possible", "security_fix_likely")


def test_algorithmic_growth_without_security_context_is_not_escalated():
    func_diff = {
        "roles_a": ["codec"],
        "roles_b": ["codec"],
        "interestingness": 25.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [0x800],
            "size_delta_pct": 18.0,
            "blocks_delta": 8,
            "instr_delta": 40,
            "compare_delta": 8,
            "branch_delta": 6,
            "api_families_added": [],
            "string_categories_added": [],
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("behavior_change", "refactor")


def test_parser_growth_with_security_context_still_escalates():
    func_diff = {
        "roles_a": ["parser"],
        "roles_b": ["parser", "validator"],
        "interestingness": 20.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["invalid header length"],
            "strings_removed": [],
            "constants_added": [0x100],
            "size_delta_pct": 15.0,
            "blocks_delta": 5,
            "instr_delta": 24,
            "compare_delta": 4,
            "branch_delta": 5,
            "api_families_added": ["validation"],
            "string_categories_added": ["error", "http"],
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("security_fix_possible", "security_fix_likely")


def test_benchmark_name_fallback_does_not_escalate_algorithmic_growth():
    func_diff = {
        "name_a": "_BMK_benchCLevel",
        "name_b": "_BMK_benchCLevels",
        "interestingness": 18.0,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [0x80, 0x200],
            "size_delta_pct": 22.0,
            "blocks_delta": 8,
            "instr_delta": 30,
            "compare_delta": 6,
            "branch_delta": 8,
            "api_families_added": [],
            "string_categories_added": [],
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] in ("behavior_change", "refactor")


def test_synthetic_light_backend_scope_uses_behavior_label():
    func_diff = {
        "name_a": "section:__TEXT:__text",
        "name_b": "section:__TEXT:__text",
        "interestingness": 1.2,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": ["executable section"],
            "strings_removed": [],
            "constants_added": [],
            "size_delta_pct": 0.1,
            "blocks_delta": 0,
            "instr_delta": 0,
            "compare_delta": 0,
            "branch_delta": 0,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "behavior_change"


def test_modest_structure_only_change_is_unchanged():
    func_diff = {
        "interestingness": 3.5,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "constants_removed": [],
            "constant_buckets_added": [],
            "constant_buckets_removed": [],
            "api_families_added": [],
            "api_families_removed": [],
            "string_categories_added": [],
            "string_categories_removed": [],
            "size_delta_pct": 8.0,
            "blocks_delta": 2,
            "instr_delta": 12,
            "compare_delta": 0,
            "branch_delta": -3,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "unchanged"


def test_large_structure_only_change_is_refactor():
    func_diff = {
        "interestingness": 4.5,
        "signals": {
            "ext_calls_added": [],
            "ext_calls_removed": [],
            "calls_added": [],
            "calls_removed": [],
            "strings_added": [],
            "strings_removed": [],
            "constants_added": [],
            "constants_removed": [],
            "constant_buckets_added": [],
            "constant_buckets_removed": [],
            "api_families_added": [],
            "api_families_removed": [],
            "string_categories_added": [],
            "string_categories_removed": [],
            "size_delta_pct": 24.0,
            "blocks_delta": 6,
            "instr_delta": 40,
            "compare_delta": 0,
            "branch_delta": -2,
        },
    }
    result = triage_function(func_diff)
    assert result["triage_label"] == "refactor"


def test_analyze_match_ignores_auto_internal_call_address_churn():
    func_a = {
        "called_functions": [
            {"name": "FUN_1000", "entry": "0x1000", "is_external": False},
            {"name": "printf", "entry": None, "is_external": True},
        ],
        "strings": [],
        "constants": [],
        "constant_buckets": [],
        "api_families": [],
        "string_categories": [],
        "mnemonic_hist": {},
        "size": 100,
        "block_count": 10,
        "instr_count": 20,
    }
    func_b = {
        "called_functions": [
            {"name": "FUN_2000", "entry": "0x2000", "is_external": False},
            {"name": "printf", "entry": None, "is_external": True},
        ],
        "strings": [],
        "constants": [],
        "constant_buckets": [],
        "api_families": [],
        "string_categories": [],
        "mnemonic_hist": {},
        "size": 100,
        "block_count": 10,
        "instr_count": 20,
    }
    signals = analyze_match(
        func_a,
        func_b,
        map_entry_a_to_b={"0x1000": "0x2000"},
        map_entry_b_to_a={"0x2000": "0x1000"},
        map_a_to_b={"FUN_1000": "FUN_2000"},
        map_b_to_a={"FUN_2000": "FUN_1000"},
    )
    assert signals["calls_added"] == []
    assert signals["calls_removed"] == []


def test_analyze_diff_re_enriches_cached_features_with_roles():
    features = {
        "binary": "a",
        "functions": [{
            "name": "parse_request",
            "entry": "0x1000",
            "size": 100,
            "instr_count": 20,
            "block_count": 5,
            "mnemonic_hist": {"cmp": 2, "b.eq": 2},
            "mnemonic_bigrams": {},
            "strings": ["invalid header"],
            "constants": [],
            "called_functions": [],
            "callers": [],
        }],
    }
    match_data = {
        "binary_a": "a",
        "binary_b": "b",
        "matches": [{
            "name_a": "parse_request",
            "name_b": "parse_request",
            "entry_a": "0x1000",
            "entry_b": "0x1000",
            "score": 0.9,
            "method": "test",
            "uncertain": False,
        }],
        "unmatched_a": [],
        "unmatched_b": [],
    }
    diff = analyze_diff(features, features, match_data)
    assert "parser" in diff["functions"][0]["roles_a"]


def test_analyze_diff_suppresses_repeated_low_information_families():
    functions_a = []
    functions_b = []
    matches = []
    for i in range(4):
        name_a = f"FUN_A{i}"
        name_b = f"FUN_B{i}"
        fa = {
            "name": name_a,
            "entry": f"0xA{i}",
            "size": 460,
            "instr_count": 100,
            "block_count": 10,
            "mnemonic_hist": {"cmp": 4, "b.eq": 3},
            "mnemonic_bigrams": {},
            "strings": [],
            "constants": [],
            "called_functions": [{"name": f"sub_old_{i}", "is_external": False, "entry": f"0xC{i}"}],
            "callers": [],
        }
        fb = {
            "name": name_b,
            "entry": f"0xB{i}",
            "size": 436,
            "instr_count": 94,
            "block_count": 10,
            "mnemonic_hist": {"cmp": 5},
            "mnemonic_bigrams": {},
            "strings": [],
            "constants": [],
            "called_functions": [{"name": f"sub_new_{i}", "is_external": False, "entry": f"0xD{i}"}],
            "callers": [],
        }
        functions_a.append(fa)
        functions_b.append(fb)
        matches.append({
            "name_a": name_a,
            "name_b": name_b,
            "entry_a": fa["entry"],
            "entry_b": fb["entry"],
            "score": 0.6,
            "method": "test",
            "uncertain": False,
        })

    diff = analyze_diff(
        {"binary": "a", "functions": functions_a},
        {"binary": "b", "functions": functions_b},
        {"binary_a": "a", "binary_b": "b", "matches": matches, "unmatched_a": [], "unmatched_b": []},
    )
    assert all(item["interestingness"] <= 1.4 for item in diff["functions"])


def test_analyze_diff_suppresses_repeated_format_only_family():
    functions_a = []
    functions_b = []
    matches = []
    for i in range(4):
        name_a = f"FUN_FMT_A{i}"
        name_b = f"FUN_FMT_B{i}"
        fa = {
            "name": name_a,
            "entry": f"0xFA{i}",
            "size": 300,
            "instr_count": 60,
            "block_count": 6,
            "mnemonic_hist": {"b.eq": 4},
            "mnemonic_bigrams": {},
            "strings": [],
            "constants": [],
            "called_functions": [{"name": f"sub_old_{i}", "is_external": False, "entry": f"0xFC{i}"}],
            "callers": [],
        }
        fb = {
            "name": name_b,
            "entry": f"0xFB{i}",
            "size": 360,
            "instr_count": 84,
            "block_count": 6,
            "mnemonic_hist": {"b.eq": 11},
            "mnemonic_bigrams": {},
            "strings": ["%s (%s) and %s (%s) %s"],
            "constants": [],
            "called_functions": [
                {"name": f"sub_new_{i}_0", "is_external": False, "entry": f"0xFD{i}0"},
                {"name": f"sub_new_{i}_1", "is_external": False, "entry": f"0xFD{i}1"},
                {"name": f"sub_new_{i}_2", "is_external": False, "entry": f"0xFD{i}2"},
                {"name": f"sub_new_{i}_3", "is_external": False, "entry": f"0xFD{i}3"},
            ],
            "callers": [],
        }
        functions_a.append(fa)
        functions_b.append(fb)
        matches.append({
            "name_a": name_a,
            "name_b": name_b,
            "entry_a": fa["entry"],
            "entry_b": fb["entry"],
            "score": 0.6,
            "method": "test",
            "uncertain": False,
        })

    diff = analyze_diff(
        {"binary": "a", "functions": functions_a},
        {"binary": "b", "functions": functions_b},
        {"binary_a": "a", "binary_b": "b", "matches": matches, "unmatched_a": [], "unmatched_b": []},
    )
    assert all(item["interestingness"] <= 2.0 for item in diff["functions"])
