"""PatchTriage CLI — Binary Patch Diffing and Triage Tool."""

import argparse
import json
import sys
from pathlib import Path


def cmd_extract(args):
    """Extract features from a binary using Ghidra headless."""
    from .extract import run_extract
    run_extract(args.binary, args.output, ghidra_path=args.ghidra)


def cmd_diff(args):
    """Diff two feature files and produce match + change analysis."""
    from .matcher import match_functions
    from .analyzer import analyze_diff

    with open(args.features_a) as f:
        feat_a = json.load(f)
    with open(args.features_b) as f:
        feat_b = json.load(f)

    print(f"Matching {feat_a['num_functions']} vs {feat_b['num_functions']} functions...")
    match_data = match_functions(feat_a, feat_b, threshold=args.threshold)
    print(f"  {match_data['num_matches']} matched, "
          f"{match_data['num_unmatched_a']} unmatched in A, "
          f"{match_data['num_unmatched_b']} unmatched in B")

    print("Analyzing changes...")
    diff_data = analyze_diff(feat_a, feat_b, match_data)

    with open(args.output, "w") as f:
        json.dump(diff_data, f, indent=2, default=str)
    print(f"Diff written to {args.output}")


def cmd_report(args):
    """Generate a Markdown report from diff.json."""
    from .triage import triage_diff
    from .report import generate_markdown, generate_html

    with open(args.diff_json) as f:
        diff_data = json.load(f)

    print("Running triage heuristics...")
    diff_data = triage_diff(diff_data)

    md = generate_markdown(diff_data, top_n=args.top)

    output = args.output or args.diff_json.replace(".json", "_report.md")
    with open(output, "w") as f:
        f.write(md)
    print(f"Report written to {output}")

    if args.html:
        html_path = output.replace(".md", ".html")
        html = generate_html(md)
        with open(html_path, "w") as f:
            f.write(html)
        print(f"HTML report written to {html_path}")

    # Also save the triaged JSON back
    triaged_path = args.diff_json.replace(".json", "_triaged.json")
    with open(triaged_path, "w") as f:
        json.dump(diff_data, f, indent=2, default=str)
    print(f"Triaged data written to {triaged_path}")


def cmd_explain(args):
    """Add LLM explanations to a diff report."""
    from .triage import triage_diff
    from .llm_explain import explain_top_functions
    from .report import generate_markdown

    with open(args.diff_json) as f:
        diff_data = json.load(f)

    # Ensure triage is applied
    diff_data = triage_diff(diff_data)

    # Add LLM explanations
    diff_data = explain_top_functions(diff_data, top_n=args.top, api_key=args.api_key)

    # Update the report to include LLM summaries
    md = generate_markdown(diff_data, top_n=args.top)

    # Append LLM summaries section
    lines = [md, "", "## LLM Explanations", ""]
    for func in diff_data.get("functions", []):
        if "llm_summary" in func:
            lines.append(f"### `{func['name_a']}`")
            lines.append(f"**Category:** {func.get('llm_category', 'unknown')}")
            lines.append(f"**Summary:** {func['llm_summary']}")
            lines.append("")

    full_report = "\n".join(lines)
    output = args.output or args.diff_json.replace(".json", "_explained.md")
    with open(output, "w") as f:
        f.write(full_report)
    print(f"Explained report written to {output}")

    # Save enriched JSON
    enriched_path = args.diff_json.replace(".json", "_explained.json")
    with open(enriched_path, "w") as f:
        json.dump(diff_data, f, indent=2, default=str)


def main():
    parser = argparse.ArgumentParser(
        prog="patchtriage",
        description="PatchTriage — Binary Patch Diffing and Triage CLI",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    # --- extract ---
    p_ext = sub.add_parser("extract", help="Extract features from a binary via Ghidra")
    p_ext.add_argument("binary", help="Path to input binary")
    p_ext.add_argument("-o", "--output", default="features.json", help="Output JSON path")
    p_ext.add_argument("--ghidra", default=None, help="Path to analyzeHeadless")
    p_ext.set_defaults(func=cmd_extract)

    # --- diff ---
    p_diff = sub.add_parser("diff", help="Diff two feature files")
    p_diff.add_argument("features_a", help="Features JSON for binary A")
    p_diff.add_argument("features_b", help="Features JSON for binary B")
    p_diff.add_argument("-o", "--output", default="diff.json", help="Output diff JSON path")
    p_diff.add_argument("-t", "--threshold", type=float, default=0.3,
                        help="Minimum similarity threshold for matching (default: 0.3)")
    p_diff.set_defaults(func=cmd_diff)

    # --- report ---
    p_rep = sub.add_parser("report", help="Generate report from diff JSON")
    p_rep.add_argument("diff_json", help="Path to diff.json")
    p_rep.add_argument("-o", "--output", default=None, help="Output report path")
    p_rep.add_argument("--top", type=int, default=30, help="Number of top functions to show")
    p_rep.add_argument("--html", action="store_true", help="Also generate HTML report")
    p_rep.set_defaults(func=cmd_report)

    # --- explain ---
    p_exp = sub.add_parser("explain", help="Add LLM explanations to diff (optional)")
    p_exp.add_argument("diff_json", help="Path to diff.json")
    p_exp.add_argument("-o", "--output", default=None, help="Output report path")
    p_exp.add_argument("--top", type=int, default=10, help="Number of functions to explain")
    p_exp.add_argument("--api-key", default=None, help="OpenAI API key (or set OPENAI_API_KEY)")
    p_exp.set_defaults(func=cmd_explain)

    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
