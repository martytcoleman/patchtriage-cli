"""Tests for triage heuristics."""

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
