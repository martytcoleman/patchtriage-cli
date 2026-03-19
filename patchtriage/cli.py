"""PatchTriage CLI — Binary Patch Diffing and Triage Tool."""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path


def _write_json(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=2, default=str)


def _run_pipeline(binary_a: str, binary_b: str, *,
                  outdir: str | None = None,
                  llm: bool = False,
                  provider: str | None = None,
                  api_key: str | None = None,
                  top: int = 30,
                  html: bool = False,
                  threshold: float = 0.3,
                  ghidra: str | None = None,
                  stripped: bool = False,
                  force_extract: bool = False,
                  profile: str = "auto",
                  backend: str = "auto"):
    """Core pipeline: extract -> diff -> triage -> (llm) -> report."""
    from .classify import classify_binary
    from .extract import run_extract
    from .light import run_light_extract
    from .native import run_native_extract
    from .matcher import match_functions
    from .analyzer import analyze_diff
    from .triage import triage_diff
    from .report import generate_markdown, generate_html
    from .console import print_report, _c, DIM, CYAN, BOLD, GREEN, RED

    binary_a = os.path.abspath(binary_a)
    binary_b = os.path.abspath(binary_b)

    # Determine output directory
    if outdir:
        os.makedirs(outdir, exist_ok=True)
    else:
        outdir = os.path.dirname(binary_a) or "."

    name_a = Path(binary_a).stem
    name_b = Path(binary_b).stem
    feat_a_path = os.path.join(outdir, f"{name_a}_features.json")
    feat_b_path = os.path.join(outdir, f"{name_b}_features.json")
    diff_path = os.path.join(outdir, "diff.json")

    class_a = classify_binary(binary_a)
    class_b = classify_binary(binary_b)
    selected_backend = backend
    if backend == "auto":
        if class_a["language"] in {"go", "rust"} or class_b["language"] in {"go", "rust"}:
            selected_backend = "light"
        elif class_a["symbolized"] and class_b["symbolized"] and not (class_a["challenging"] or class_b["challenging"]):
            selected_backend = "native"
        elif class_a["challenging"] or class_b["challenging"]:
            selected_backend = "light"
        else:
            selected_backend = "ghidra"
    print(f"Selected backend: {selected_backend}", flush=True)

    # ── Step 1: Extract ──
    if selected_backend == "light":
        feat_a = run_light_extract(binary_a, feat_a_path, reuse_cached=not force_extract)
        feat_b = run_light_extract(binary_b, feat_b_path, reuse_cached=not force_extract)
    elif selected_backend == "native":
        feat_a = run_native_extract(binary_a, feat_a_path, reuse_cached=not force_extract)
        feat_b = run_native_extract(binary_b, feat_b_path, reuse_cached=not force_extract)
    else:
        feat_a = run_extract(
            binary_a, feat_a_path, ghidra_path=ghidra,
            reuse_cached=not force_extract, profile=profile,
        )
        feat_b = run_extract(
            binary_b, feat_b_path, ghidra_path=ghidra,
            reuse_cached=not force_extract, profile=profile,
        )

    # ── Step 2: Match + Analyze ──
    print(f"\nMatching {_c(BOLD, str(feat_a['num_functions']))} vs "
          f"{_c(BOLD, str(feat_b['num_functions']))} functions...")
    match_data = match_functions(feat_a, feat_b, threshold=threshold, stripped=stripped)
    print(f"  {_c(GREEN, str(match_data['num_matches']))} matched, "
          f"{_c(RED, str(match_data['num_unmatched_a']))} unmatched in A, "
          f"{_c(RED, str(match_data['num_unmatched_b']))} unmatched in B")

    print(f"{_c(DIM, 'Analyzing changes...')}")
    diff_data = analyze_diff(feat_a, feat_b, match_data)

    _write_json(diff_path, diff_data)

    # ── Step 3: Triage ──
    print(f"{_c(DIM, 'Running triage heuristics...')}")
    diff_data = triage_diff(diff_data)

    # ── Step 4: LLM (if requested) ──
    if llm:
        from .llm_explain import explain_top_functions, generate_executive_summary
        diff_data = explain_top_functions(
            diff_data, top_n=top, provider=provider, api_key=api_key,
        )
        exec_summary = generate_executive_summary(
            diff_data, provider=provider, api_key=api_key,
        )
        if exec_summary:
            diff_data["executive_summary"] = exec_summary

    # ── Print to terminal ──
    print_report(diff_data, top_n=top)

    # ── Write files ──
    md_path = os.path.join(outdir, "report.md")
    md = generate_markdown(diff_data, top_n=top)
    with open(md_path, "w") as f:
        f.write(md)
    print(f"{_c(DIM, 'Report written to')} {_c(CYAN, md_path)}")

    if html:
        html_path = os.path.join(outdir, "report.html")
        html_content = generate_html(md)
        with open(html_path, "w") as f:
            f.write(html_content)
        print(f"{_c(DIM, 'HTML written to')} {_c(CYAN, html_path)}")

    json_path = os.path.join(outdir, "report.json")
    _write_json(json_path, diff_data)
    print(f"{_c(DIM, 'Data written to')} {_c(CYAN, json_path)}")

    return diff_data


def cmd_extract(args):
    """Extract features from a single binary."""
    from .classify import classify_binary
    from .extract import run_extract
    from .light import run_light_extract
    from .native import run_native_extract

    output = args.output
    if output is None:
        output = os.path.abspath(f"{Path(args.binary).stem}_features.json")
    selected_backend = args.backend
    if selected_backend == "auto":
        info = classify_binary(args.binary)
        if info["language"] in {"go", "rust"}:
            selected_backend = "light"
        elif info["symbolized"] and not info["challenging"]:
            selected_backend = "native"
        elif info["challenging"]:
            selected_backend = "light"
        else:
            selected_backend = "ghidra"
    if selected_backend == "light":
        data = run_light_extract(args.binary, output, reuse_cached=not args.force)
    elif selected_backend == "native":
        data = run_native_extract(args.binary, output, reuse_cached=not args.force)
    else:
        data = run_extract(
            args.binary,
            output,
            ghidra_path=args.ghidra,
            reuse_cached=not args.force,
            profile=args.profile,
        )
    print(
        f"Summary: {data['num_functions']} functions, arch={data.get('arch', 'unknown')}, "
        f"profile={data.get('analysis_profile', 'unknown')}, backend={data.get('backend', selected_backend)}"
    )


def cmd_diff(args):
    """Diff two extracted feature JSON files and emit diff.json."""
    from .matcher import match_functions
    from .analyzer import analyze_diff
    from .console import _c, BOLD, DIM, GREEN, RED, CYAN

    with open(args.features_a) as f:
        feat_a = json.load(f)
    with open(args.features_b) as f:
        feat_b = json.load(f)

    print(f"\nMatching {_c(BOLD, str(feat_a['num_functions']))} vs "
          f"{_c(BOLD, str(feat_b['num_functions']))} functions...")
    match_data = match_functions(feat_a, feat_b, threshold=args.threshold, stripped=args.stripped)
    print(f"  {_c(GREEN, str(match_data['num_matches']))} matched, "
          f"{_c(RED, str(match_data['num_unmatched_a']))} unmatched in A, "
          f"{_c(RED, str(match_data['num_unmatched_b']))} unmatched in B")
    print(f"{_c(DIM, 'Analyzing changes...')}")
    diff_data = analyze_diff(feat_a, feat_b, match_data)

    output = args.output or os.path.abspath("diff.json")
    _write_json(output, diff_data)
    print(f"{_c(DIM, 'Diff written to')} {_c(CYAN, output)}")
    top = diff_data.get("functions", [])[: min(5, len(diff_data.get("functions", [])))]
    if top:
        print(_c(DIM, "Top changed functions:"))
        for func in top:
            print(
                f"  {func['name_a']} -> {func['name_b']} "
                f"(interest={func['interestingness']}, match={func['match_score']})"
            )


def cmd_run(args):
    """Run full pipeline: extract -> diff -> triage -> report."""
    _run_pipeline(
        args.binary_a, args.binary_b,
        outdir=args.outdir,
        llm=args.llm,
        provider=args.provider,
        api_key=args.api_key,
        top=args.top,
        html=args.html,
        threshold=args.threshold,
        ghidra=args.ghidra,
        stripped=args.stripped,
        force_extract=args.force,
        profile=args.profile,
        backend=args.backend,
    )


def cmd_report(args):
    """Generate triage report from pre-computed diff.json."""
    from .triage import triage_diff
    from .report import generate_markdown, generate_html
    from .console import print_report, _c, DIM, CYAN

    with open(args.diff_json) as f:
        diff_data = json.load(f)

    print(f"{_c(DIM, 'Running triage heuristics...')}")
    diff_data = triage_diff(diff_data)

    if args.llm:
        from .llm_explain import explain_top_functions, generate_executive_summary
        diff_data = explain_top_functions(
            diff_data, top_n=args.top,
            provider=args.provider, api_key=args.api_key,
        )
        exec_summary = generate_executive_summary(
            diff_data, provider=args.provider, api_key=args.api_key,
        )
        if exec_summary:
            diff_data["executive_summary"] = exec_summary

    print_report(diff_data, top_n=args.top)

    output = args.output or args.diff_json.replace(".json", "_report.md")
    md = generate_markdown(diff_data, top_n=args.top)
    with open(output, "w") as f:
        f.write(md)
    print(f"{_c(DIM, 'Report written to')} {_c(CYAN, output)}")

    if args.html:
        html_path = output.replace(".md", ".html")
        html = generate_html(md)
        with open(html_path, "w") as f:
            f.write(html)
        print(f"{_c(DIM, 'HTML written to')} {_c(CYAN, html_path)}")

    json_path = args.diff_json.replace(".json", "_triaged.json")
    _write_json(json_path, diff_data)
    print(f"{_c(DIM, 'Data written to')} {_c(CYAN, json_path)}")


def cmd_evaluate(args):
    """Evaluate fixture corpus for matching and ranking quality."""
    from .console import _c, BOLD, CYAN, DIM
    from .evaluate import evaluate_corpus, load_corpus

    corpus = load_corpus(args.corpus_json)
    result = evaluate_corpus(corpus)

    print(_c(BOLD, "PatchTriage Evaluation"))
    print(f"{_c(DIM, 'Corpus:')} {_c(CYAN, args.corpus_json)}")
    print(f"{_c(DIM, 'Cases:')} {result['summary']['cases']}")
    print(f"{_c(DIM, 'Match recall:')} {result['summary']['match_recall']}")
    print(f"{_c(DIM, 'Top-3 security hit rate:')} {result['summary']['top3_security_hit_rate']}")

    for case in result["cases"]:
        print(
            f"  {case['name']}: recall={case['match_recall']} "
            f"precision={case['match_precision']} top3_hit={case['top3_security_hit']}"
        )


def main():
    parser = argparse.ArgumentParser(
        prog="patchtriage",
        description="PatchTriage — Binary Patch Diffing and Triage CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- run (primary command) ---
    p_run = sub.add_parser("run", help="Full pipeline: binary A + binary B -> report")
    p_run.add_argument("binary_a", help="Path to binary version A (before)")
    p_run.add_argument("binary_b", help="Path to binary version B (after)")
    p_run.add_argument("-o", "--outdir", default=None,
                        help="Output directory (default: same dir as binary_a)")
    p_run.add_argument("--top", type=int, default=30, help="Number of top functions to show")
    p_run.add_argument("--html", action="store_true", help="Also generate HTML report")
    p_run.add_argument("--llm", action="store_true",
                        help="Enable LLM analysis (uses GROK_API_KEY or OPENAI_API_KEY from .env)")
    p_run.add_argument("--provider", choices=["openai", "grok"], default=None,
                        help="LLM provider (auto-detected from .env if not set)")
    p_run.add_argument("--api-key", default=None, help="API key (or set in .env)")
    p_run.add_argument("-t", "--threshold", type=float, default=0.3,
                        help="Similarity threshold for matching (default: 0.3)")
    p_run.add_argument("--ghidra", default=None, help="Path to Ghidra install directory")
    p_run.add_argument("--stripped", action="store_true",
                        help="Ignore function names during matching; use structural/contextual signals only")
    p_run.add_argument("--force", action="store_true",
                        help="Force re-extraction even if cached feature JSONs already match the input binaries")
    p_run.add_argument("--profile", choices=["auto", "fast", "full"], default="auto",
                        help="Extraction profile: auto selects based on binary pre-scan")
    p_run.add_argument("--backend", choices=["auto", "ghidra", "native", "light"], default="auto",
                        help="Extraction backend: auto picks native for symbolized binaries and light for likely Go/Rust binaries")
    p_run.set_defaults(func=cmd_run)

    # --- extract ---
    p_extract = sub.add_parser("extract", help="Extract per-function features from a binary")
    p_extract.add_argument("binary", help="Path to binary to analyze")
    p_extract.add_argument("-o", "--output", default=None, help="Output feature JSON path")
    p_extract.add_argument("--ghidra", default=None, help="Path to Ghidra install directory")
    p_extract.add_argument("--force", action="store_true",
                           help="Force extraction even if a matching cached feature file already exists")
    p_extract.add_argument("--profile", choices=["auto", "fast", "full"], default="auto",
                           help="Extraction profile: auto selects based on binary pre-scan")
    p_extract.add_argument("--backend", choices=["auto", "ghidra", "native", "light"], default="auto",
                           help="Extraction backend: auto picks native for symbolized binaries and light for likely Go/Rust binaries")
    p_extract.set_defaults(func=cmd_extract)

    # --- diff ---
    p_diff = sub.add_parser("diff", help="Diff two extracted feature JSON files")
    p_diff.add_argument("features_a", help="Path to features JSON for version A")
    p_diff.add_argument("features_b", help="Path to features JSON for version B")
    p_diff.add_argument("-o", "--output", default=None, help="Output diff JSON path")
    p_diff.add_argument("-t", "--threshold", type=float, default=0.3,
                        help="Similarity threshold for matching (default: 0.3)")
    p_diff.add_argument("--stripped", action="store_true",
                        help="Ignore function names during matching; use structural/contextual signals only")
    p_diff.set_defaults(func=cmd_diff)

    # --- report (from pre-computed diff.json) ---
    p_rep = sub.add_parser("report", help="Report from pre-computed diff.json")
    p_rep.add_argument("diff_json", help="Path to diff.json")
    p_rep.add_argument("-o", "--output", default=None, help="Output report path")
    p_rep.add_argument("--top", type=int, default=30, help="Number of top functions to show")
    p_rep.add_argument("--html", action="store_true", help="Also generate HTML report")
    p_rep.add_argument("--llm", action="store_true",
                        help="Enable LLM analysis (uses GROK_API_KEY or OPENAI_API_KEY from .env)")
    p_rep.add_argument("--provider", choices=["openai", "grok"], default=None,
                        help="LLM provider (auto-detected from .env if not set)")
    p_rep.add_argument("--api-key", default=None, help="API key (or set in .env)")
    p_rep.set_defaults(func=cmd_report)

    p_eval = sub.add_parser("evaluate", help="Evaluate fixture corpus for matching and triage quality")
    p_eval.add_argument("corpus_json", help="Path to evaluation corpus JSON")
    p_eval.set_defaults(func=cmd_evaluate)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
