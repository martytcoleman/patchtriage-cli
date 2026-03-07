"""Optional LLM-powered explanations for diff results."""

from __future__ import annotations

import json
import os
import sys


def _build_prompt(func_diff: dict) -> str:
    """Build a structured prompt for a single function diff."""
    signals = func_diff.get("signals", {})
    triage = func_diff.get("triage_label", "unknown")
    rationale = func_diff.get("triage_rationale", [])

    evidence = {
        "function_name": func_diff.get("name_a", "?"),
        "triage_label": triage,
        "triage_rationale": rationale,
        "size_change": f"{signals.get('size_a', 0)} -> {signals.get('size_b', 0)} ({signals.get('size_delta_pct', 0):+.1f}%)",
        "blocks_change": f"{signals.get('blocks_a', 0)} -> {signals.get('blocks_b', 0)}",
        "ext_calls_added": signals.get("ext_calls_added", []),
        "ext_calls_removed": signals.get("ext_calls_removed", []),
        "strings_added": signals.get("strings_added", [])[:10],
        "strings_removed": signals.get("strings_removed", [])[:10],
        "constants_added": [hex(c) if isinstance(c, int) else c for c in signals.get("constants_added", [])[:10]],
        "compare_delta": signals.get("compare_delta", 0),
        "branch_delta": signals.get("branch_delta", 0),
    }

    return f"""You are a binary patch analyst. Based ONLY on the evidence below, write a 2-4 sentence summary of what changed in this function and why it might matter.

If the evidence is insufficient to determine the purpose, say "Insufficient evidence to determine purpose."

Evidence:
{json.dumps(evidence, indent=2)}

Respond with a JSON object:
{{"summary": "...", "category": "one of: input_validation, memory_safety, crypto, logging, error_handling, feature_change, refactor, unknown"}}"""


def explain_top_functions(diff_data: dict, top_n: int = 10, api_key: str | None = None) -> dict:
    """Add LLM explanations to the top N most interesting functions.

    Requires the `openai` package and an API key (via OPENAI_API_KEY env or parameter).
    Returns the modified diff_data.
    """
    try:
        from openai import OpenAI
    except ImportError:
        print("Error: openai package not installed. Run: pip install openai", file=sys.stderr)
        return diff_data

    key = api_key or os.environ.get("OPENAI_API_KEY", "")
    if not key:
        print("Error: set OPENAI_API_KEY environment variable or pass --api-key", file=sys.stderr)
        return diff_data

    client = OpenAI(api_key=key)

    funcs = diff_data.get("functions", [])
    interesting = [f for f in funcs if f.get("interestingness", 0) > 0][:top_n]

    print(f"Generating LLM explanations for {len(interesting)} functions...")

    for func in interesting:
        prompt = _build_prompt(func)
        try:
            response = client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.2,
                max_tokens=300,
            )
            content = response.choices[0].message.content.strip()
            # Try to parse as JSON
            try:
                parsed = json.loads(content)
                func["llm_summary"] = parsed.get("summary", content)
                func["llm_category"] = parsed.get("category", "unknown")
            except json.JSONDecodeError:
                func["llm_summary"] = content
                func["llm_category"] = "unknown"
        except Exception as e:
            func["llm_summary"] = f"LLM error: {e}"
            func["llm_category"] = "error"

    return diff_data
