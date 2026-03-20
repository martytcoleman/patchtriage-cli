"""Tests for function matching logic."""

import pytest
from patchtriage.matcher import compute_similarity, match_functions, _jaccard, _cosine_hist


def test_jaccard_identical():
    assert _jaccard({"a", "b"}, {"a", "b"}) == 1.0

def test_jaccard_disjoint():
    assert _jaccard({"a"}, {"b"}) == 0.0

def test_jaccard_empty():
    assert _jaccard(set(), set()) == 1.0

def test_cosine_identical():
    h = {"mov": 10, "call": 5}
    assert abs(_cosine_hist(h, h) - 1.0) < 1e-6

def test_cosine_disjoint():
    assert _cosine_hist({"mov": 1}, {"call": 1}) == 0.0


def _make_func(name, size=100, strings=None, calls=None, hist=None):
    return {
        "name": name,
        "entry": f"0x{hash(name) & 0xFFFF:04x}",
        "size": size,
        "instr_count": size // 2,
        "block_count": size // 10,
        "mnemonic_hist": hist or {"mov": 10, "call": 3, "ret": 1},
        "mnemonic_bigrams": {},
        "strings": strings or [],
        "constants": [],
        "called_functions": [{"name": c, "is_external": True} for c in (calls or [])],
        "callers": [],
    }


def test_identical_functions_high_score():
    f = _make_func("foo", strings=["hello"], calls=["printf"])
    score = compute_similarity(f, f)
    assert score > 0.8


def test_different_functions_low_score():
    fa = _make_func("foo", size=100, strings=["hello"], calls=["printf"],
                     hist={"mov": 20, "call": 5})
    fb = _make_func("bar", size=500, strings=["goodbye"], calls=["malloc", "free"],
                     hist={"push": 15, "pop": 15})
    score = compute_similarity(fa, fb)
    assert score < 0.5


def test_match_by_name():
    feat_a = {"functions": [_make_func("main"), _make_func("helper")], "binary": "a"}
    feat_b = {"functions": [_make_func("helper"), _make_func("main")], "binary": "b"}
    result = match_functions(feat_a, feat_b)
    assert result["num_matches"] == 2
    names = {(m["name_a"], m["name_b"]) for m in result["matches"]}
    assert ("main", "main") in names
    assert ("helper", "helper") in names


def test_unmatched_functions():
    fa = _make_func("only_in_a", size=50, strings=["aaa"], calls=["read"],
                     hist={"mov": 30})
    fb = _make_func("only_in_b", size=500, strings=["zzz"], calls=["write"],
                     hist={"push": 30, "pop": 30})
    feat_a = {"functions": [fa], "binary": "a"}
    feat_b = {"functions": [fb], "binary": "b"}
    result = match_functions(feat_a, feat_b, threshold=0.99)
    assert result["num_unmatched_a"] >= 1
    assert result["num_unmatched_b"] >= 1


def test_match_in_stripped_mode_uses_non_name_signals():
    fa = _make_func("FUN_1000", size=120, strings=["invalid header"], calls=["strcpy"])
    fb = _make_func("FUN_2000", size=125, strings=["invalid header"], calls=["strncpy"])
    feat_a = {"functions": [fa], "binary": "a"}
    feat_b = {"functions": [fb], "binary": "b"}
    result = match_functions(feat_a, feat_b, threshold=0.2, stripped=True)
    assert result["num_matches"] == 1


def test_uncertain_match_flag_set_when_alternatives_are_close():
    fa1 = _make_func("FUN_A1", size=100, strings=["same"], calls=["printf"])
    fa2 = _make_func("FUN_A2", size=100, strings=["same"], calls=["printf"])
    fb1 = _make_func("FUN_B1", size=100, strings=["same"], calls=["printf"])
    fb2 = _make_func("FUN_B2", size=100, strings=["same"], calls=["printf"])
    result = match_functions(
        {"functions": [fa1, fa2], "binary": "a"},
        {"functions": [fb1, fb2], "binary": "b"},
        threshold=0.2,
        stripped=True,
        uncertain_gap=0.2,
    )
    assert result["num_matches"] == 2
    assert any(match["uncertain"] for match in result["matches"])


def test_repair_pairs_a_with_unmatched_same_named_b_after_bad_bipartite():
    """Bipartite can assign A to the wrong B row while the real symbol remains unmatched.

    Here size blocking prevents any similarity edge to the true ``_ossl_sleep`` on B,
    so only ``_kmac_update`` competes — then repair moves the match to the leftover
    same-named B row.
    """
    fa = _make_func(
        "_ossl_sleep",
        size=100,
        strings=["token"],
        calls=["ext"],
        hist={"mov": 10, "call": 3, "ret": 1},
    )
    fb_kmac = _make_func(
        "_kmac_update",
        size=105,
        strings=["token"],
        calls=["ext"],
        hist={"mov": 10, "call": 3, "ret": 1},
    )
    fb_sleep = _make_func(
        "_ossl_sleep",
        size=900,
        strings=["other"],
        calls=["malloc"],
        hist={"push": 20, "pop": 20},
    )
    feat_a = {"functions": [fa], "binary": "a"}
    feat_b = {"functions": [fb_kmac, fb_sleep], "binary": "b"}
    result = match_functions(feat_a, feat_b, threshold=0.25, stripped=True)
    assert result["num_matches"] == 1
    m = result["matches"][0]
    assert m["name_a"] == "_ossl_sleep"
    assert m["name_b"] == "_ossl_sleep"
    assert m["method"] == "name_repair_unmatched_b"
    assert "_ossl_sleep" not in result["unmatched_b"]


def test_cross_name_implausible_blocked_below_structural_ceiling():
    """Symbolized Pass 2: unrelated names need similarity >= CROSS_NAME_MIN_SIMILARITY."""
    fa = _make_func(
        "real_name_a",
        size=150,
        strings=["a1", "a2"],
        calls=["read"],
        hist={"mov": 30, "call": 5},
    )
    fb = _make_func(
        "totally_other",
        size=160,
        strings=["z1", "z2"],
        calls=["write"],
        hist={"push": 20, "pop": 20},
    )
    s = compute_similarity(fa, fb, stripped=False)
    assert 0.30 <= s < 0.52, f"adjust fixture: similarity={s}"
    result = match_functions(
        {"functions": [fa], "binary": "a"},
        {"functions": [fb], "binary": "b"},
        threshold=0.30,
        stripped=False,
    )
    assert result["num_matches"] == 0


def test_cross_name_floor_not_applied_in_stripped_mode():
    """Stripped matching must still use structural similarity only."""
    hist = {"mov": 30, "call": 5}
    fa = _make_func(
        "FUN_1000",
        size=150,
        strings=["a1", "a2"],
        calls=["read"],
        hist=hist,
    )
    fb = _make_func(
        "FUN_2000",
        size=160,
        strings=["z1", "z2"],
        calls=["write"],
        hist={"push": 20, "pop": 20},
    )
    s = compute_similarity(fa, fb, stripped=True)
    assert s >= 0.25
    result = match_functions(
        {"functions": [fa], "binary": "a"},
        {"functions": [fb], "binary": "b"},
        threshold=0.25,
        stripped=True,
    )
    assert result["num_matches"] == 1


def test_plausible_rename_allows_similarity_at_default_threshold():
    """Renames in the same family are not subject to the cross-name floor."""
    from patchtriage.matcher import _is_plausible_rename

    hist = {"mov": 10, "call": 3, "ret": 1}
    fa = _make_func("helper", size=100, strings=["x"], calls=["c"], hist=hist)
    fb = _make_func("helper_internal", size=105, strings=["y"], calls=["d"], hist=hist)
    assert _is_plausible_rename("helper", "helper_internal")
    s = compute_similarity(fa, fb, stripped=False)
    assert s >= 0.30
    result = match_functions(
        {"functions": [fa], "binary": "a"},
        {"functions": [fb], "binary": "b"},
        threshold=0.30,
        stripped=False,
    )
    assert result["num_matches"] == 1
