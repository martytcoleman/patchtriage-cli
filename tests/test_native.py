"""Tests for the native symbolized extraction backend."""

from __future__ import annotations

from patchtriage.native import run_native_extract


def test_native_extract_on_checked_in_symbolized_binary(tmp_path):
    output = tmp_path / "server_features.json"
    data = run_native_extract("targets/open_source/server_v1", str(output), reuse_cached=False)
    assert output.exists()
    assert data["backend"] == "native"
    assert data["num_functions"] >= 5
    names = {f["name"] for f in data["functions"]}
    assert "_parse_http_request" in names
    parse_func = next(f for f in data["functions"] if f["name"] == "_parse_http_request")
    assert parse_func["instr_count"] > 0
