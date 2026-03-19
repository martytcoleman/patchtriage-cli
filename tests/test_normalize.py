"""Tests for evidence normalization helpers."""

from patchtriage.normalize import (
    bucket_constant,
    classify_api_family,
    classify_string,
    enrich_function_features,
    infer_function_roles,
    normalize_string,
    normalize_symbol,
)


def test_normalize_symbol_strips_common_suffixes():
    assert normalize_symbol("___sprintf_chk") == "sprintf"
    assert normalize_symbol("_strncpy") == "strncpy"


def test_bucket_constant_groups_similar_ranges():
    assert bucket_constant(4) == "tiny"
    assert bucket_constant(64) == "byte"
    assert bucket_constant(4096) == "pageish"


def test_classify_string_and_api_family():
    assert "error" in classify_string("Invalid header length")
    assert "http" in classify_string("Content-Length")
    assert classify_api_family("_snprintf") == "string"
    assert classify_api_family("validate_path") == "validation"


def test_enrich_function_features_adds_derived_fields():
    func = {
        "name": "parse_request",
        "strings": ["Invalid header", "Content-Length"],
        "constants": [64, 4096],
        "called_functions": [
            {"name": "_snprintf", "is_external": True},
            {"name": "validate_path", "is_external": False},
        ],
        "callers": ["main"],
        "mnemonic_hist": {"mov": 10, "cmp": 2, "je": 1},
    }
    enriched = enrich_function_features(func)
    assert "normalized_strings" in enriched
    assert "api_families" in enriched
    assert "validation" in enriched["api_families"]
    assert enriched["callgraph_context"]["caller_count"] == 1


def test_infer_function_roles_finds_parser_and_validator():
    func = {
        "name": "parse_request",
        "normalized_strings": ["invalid header length", "content-length"],
        "string_categories": ["error", "http"],
        "api_families": ["validation", "file"],
        "normalized_call_names": ["strncpy", "fprintf"],
        "instruction_groups": {"compare": 3, "branch": 4, "memory": 2},
    }
    roles = infer_function_roles(func)
    assert "parser" in roles
    assert "validator" in roles
