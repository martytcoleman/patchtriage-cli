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
    assert score > 0.9


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
