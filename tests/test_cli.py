"""CLI smoke tests for report and evaluation commands."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path


def test_cli_evaluate_command_runs():
    result = subprocess.run(
        [sys.executable, "-m", "patchtriage.cli", "evaluate", "examples/example_corpus.json"],
        capture_output=True,
        text=True,
        check=True,
    )

    assert "PatchTriage Evaluation" in result.stdout
    assert "Match recall: 1.0" in result.stdout


def test_cli_report_command_writes_outputs(tmp_path):
    output = tmp_path / "report.md"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "patchtriage.cli",
            "report",
            "targets/open_source/diff.json",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert output.exists()
    text = output.read_text()
    assert "PatchTriage Security Patch Triage Report" in text
    assert "_parse_http_request" in text
    assert "Running triage heuristics..." in result.stdout


def test_cli_run_without_outdir_leaves_binary_dir_clean(tmp_path):
    repo = Path(__file__).resolve().parents[1]
    src_a = repo / "corpus" / "open_source" / "server_v1"
    src_b = repo / "corpus" / "open_source" / "server_v2"
    a = tmp_path / "server_v1"
    b = tmp_path / "server_v2"
    shutil.copy(src_a, a)
    shutil.copy(src_b, b)

    before = {p.name for p in tmp_path.iterdir()}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "patchtriage.cli",
            "run",
            str(a),
            str(b),
        ],
        capture_output=True,
        text=True,
        check=True,
        cwd=str(repo),
    )
    after = {p.name for p in tmp_path.iterdir()}
    assert after == before
    assert "No --outdir:" in result.stdout
    assert "PatchTriage" in result.stdout or "triage" in result.stdout.lower()


def test_cli_diff_command_writes_diff(tmp_path):
    output = tmp_path / "diff.json"
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "patchtriage.cli",
            "diff",
            "targets/open_source/features_v1.json",
            "targets/open_source/features_v2.json",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    assert output.exists()
    text = output.read_text()
    assert '"total_matches"' in text
    assert "Diff written to" in result.stdout
    assert "Top changed functions:" in result.stdout
