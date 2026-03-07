#!/usr/bin/env python3
"""Generate synthetic feature files and run the full pipeline as a demo.

Usage: python examples/demo_synthetic.py
"""

import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from patchtriage.matcher import match_functions
from patchtriage.analyzer import analyze_diff
from patchtriage.triage import triage_diff
from patchtriage.report import generate_markdown, generate_html

# --- Synthetic Binary A (vulnerable version) ---
features_a = {
    "binary": "example_server_v1.0",
    "arch": "x86",
    "num_functions": 5,
    "functions": [
        {
            "name": "parse_request",
            "entry": "0x00401000",
            "size": 200,
            "instr_count": 70,
            "block_count": 8,
            "mnemonic_hist": {"mov": 20, "call": 5, "cmp": 2, "je": 2, "ret": 1, "push": 10, "pop": 10, "lea": 5, "sub": 3, "add": 2},
            "mnemonic_bigrams": {"mov,mov": 5, "cmp,je": 2, "push,mov": 3},
            "strings": ["HTTP/1.1", "Content-Length"],
            "constants": [80, 443],
            "called_functions": [
                {"name": "sprintf", "is_external": True},
                {"name": "strlen", "is_external": True},
                {"name": "malloc", "is_external": True},
            ],
            "callers": ["main"],
        },
        {
            "name": "handle_auth",
            "entry": "0x00401200",
            "size": 150,
            "instr_count": 50,
            "block_count": 6,
            "mnemonic_hist": {"mov": 15, "call": 4, "cmp": 1, "je": 1, "ret": 1, "push": 8, "pop": 8},
            "mnemonic_bigrams": {"mov,call": 3, "cmp,je": 1},
            "strings": ["admin", "password"],
            "constants": [],
            "called_functions": [
                {"name": "strcmp", "is_external": True},
                {"name": "strcpy", "is_external": True},
            ],
            "callers": ["parse_request"],
        },
        {
            "name": "send_response",
            "entry": "0x00401400",
            "size": 120,
            "instr_count": 40,
            "block_count": 4,
            "mnemonic_hist": {"mov": 12, "call": 3, "ret": 1, "push": 6, "pop": 6},
            "mnemonic_bigrams": {"mov,call": 2},
            "strings": ["200 OK", "404 Not Found"],
            "constants": [200, 404],
            "called_functions": [
                {"name": "write", "is_external": True},
                {"name": "strlen", "is_external": True},
            ],
            "callers": ["main"],
        },
        {
            "name": "log_access",
            "entry": "0x00401600",
            "size": 80,
            "instr_count": 25,
            "block_count": 3,
            "mnemonic_hist": {"mov": 8, "call": 2, "ret": 1, "push": 4, "pop": 4},
            "mnemonic_bigrams": {"mov,call": 2},
            "strings": ["access.log"],
            "constants": [],
            "called_functions": [
                {"name": "fprintf", "is_external": True},
                {"name": "fopen", "is_external": True},
            ],
            "callers": ["main"],
        },
        {
            "name": "main",
            "entry": "0x00401800",
            "size": 300,
            "instr_count": 100,
            "block_count": 12,
            "mnemonic_hist": {"mov": 30, "call": 8, "cmp": 3, "je": 3, "ret": 1, "push": 15, "pop": 15, "jmp": 2},
            "mnemonic_bigrams": {"mov,call": 5, "cmp,je": 3, "mov,mov": 8},
            "strings": ["Starting server on port %d"],
            "constants": [8080],
            "called_functions": [
                {"name": "parse_request", "is_external": False},
                {"name": "handle_auth", "is_external": False},
                {"name": "send_response", "is_external": False},
                {"name": "log_access", "is_external": False},
                {"name": "socket", "is_external": True},
                {"name": "bind", "is_external": True},
                {"name": "listen", "is_external": True},
                {"name": "accept", "is_external": True},
            ],
            "callers": [],
        },
    ],
}

# --- Synthetic Binary B (patched version) ---
features_b = {
    "binary": "example_server_v1.1",
    "arch": "x86",
    "num_functions": 6,  # one new function
    "functions": [
        {
            "name": "parse_request",
            "entry": "0x00401000",
            "size": 280,  # grew: added bounds checking
            "instr_count": 95,
            "block_count": 14,  # more blocks = more checks
            "mnemonic_hist": {"mov": 25, "call": 6, "cmp": 5, "je": 4, "jne": 2, "ret": 1, "push": 12, "pop": 12, "lea": 6, "sub": 4, "add": 3},
            "mnemonic_bigrams": {"mov,mov": 6, "cmp,je": 4, "cmp,jne": 2, "push,mov": 4},
            "strings": ["HTTP/1.1", "Content-Length", "request too large", "invalid header"],
            "constants": [80, 443, 4096, 8192],  # new bounds constants
            "called_functions": [
                {"name": "snprintf", "is_external": True},  # replaced sprintf!
                {"name": "strlen", "is_external": True},
                {"name": "malloc", "is_external": True},
                {"name": "validate_length", "is_external": False},  # new call
            ],
            "callers": ["main"],
        },
        {
            "name": "handle_auth",
            "entry": "0x00401300",
            "size": 200,  # grew: added stack protection + safer API
            "instr_count": 68,
            "block_count": 9,
            "mnemonic_hist": {"mov": 18, "call": 6, "cmp": 3, "je": 2, "jne": 1, "ret": 1, "push": 10, "pop": 10},
            "mnemonic_bigrams": {"mov,call": 4, "cmp,je": 2, "cmp,jne": 1},
            "strings": ["admin", "password", "authentication failed"],
            "constants": [64],  # buffer size limit
            "called_functions": [
                {"name": "strcmp", "is_external": True},
                {"name": "strncpy", "is_external": True},  # replaced strcpy!
                {"name": "__stack_chk_fail", "is_external": True},  # stack protection added!
            ],
            "callers": ["parse_request"],
        },
        {
            "name": "send_response",
            "entry": "0x00401500",
            "size": 125,  # barely changed
            "instr_count": 42,
            "block_count": 4,
            "mnemonic_hist": {"mov": 13, "call": 3, "ret": 1, "push": 6, "pop": 6},
            "mnemonic_bigrams": {"mov,call": 2},
            "strings": ["200 OK", "404 Not Found", "500 Internal Server Error"],
            "constants": [200, 404, 500],
            "called_functions": [
                {"name": "write", "is_external": True},
                {"name": "strlen", "is_external": True},
            ],
            "callers": ["main"],
        },
        {
            "name": "log_access",
            "entry": "0x00401700",
            "size": 80,  # unchanged
            "instr_count": 25,
            "block_count": 3,
            "mnemonic_hist": {"mov": 8, "call": 2, "ret": 1, "push": 4, "pop": 4},
            "mnemonic_bigrams": {"mov,call": 2},
            "strings": ["access.log"],
            "constants": [],
            "called_functions": [
                {"name": "fprintf", "is_external": True},
                {"name": "fopen", "is_external": True},
            ],
            "callers": ["main"],
        },
        {
            "name": "main",
            "entry": "0x00401900",
            "size": 320,
            "instr_count": 105,
            "block_count": 13,
            "mnemonic_hist": {"mov": 32, "call": 9, "cmp": 3, "je": 3, "ret": 1, "push": 16, "pop": 16, "jmp": 2},
            "mnemonic_bigrams": {"mov,call": 6, "cmp,je": 3, "mov,mov": 8},
            "strings": ["Starting server on port %d"],
            "constants": [8080],
            "called_functions": [
                {"name": "parse_request", "is_external": False},
                {"name": "handle_auth", "is_external": False},
                {"name": "send_response", "is_external": False},
                {"name": "log_access", "is_external": False},
                {"name": "validate_length", "is_external": False},
                {"name": "socket", "is_external": True},
                {"name": "bind", "is_external": True},
                {"name": "listen", "is_external": True},
                {"name": "accept", "is_external": True},
            ],
            "callers": [],
        },
        {
            "name": "validate_length",  # brand new function
            "entry": "0x00401B00",
            "size": 60,
            "instr_count": 20,
            "block_count": 4,
            "mnemonic_hist": {"mov": 5, "cmp": 3, "jge": 1, "jle": 1, "ret": 1, "push": 2, "pop": 2},
            "mnemonic_bigrams": {"cmp,jge": 1, "cmp,jle": 1},
            "strings": ["length exceeds maximum"],
            "constants": [0, 65535],
            "called_functions": [],
            "callers": ["parse_request"],
        },
    ],
}

# --- Run pipeline ---
outdir = os.path.join(os.path.dirname(__file__), "output")
os.makedirs(outdir, exist_ok=True)

# Save features
with open(os.path.join(outdir, "features_v1.json"), "w") as f:
    json.dump(features_a, f, indent=2)
with open(os.path.join(outdir, "features_v2.json"), "w") as f:
    json.dump(features_b, f, indent=2)
print("Saved synthetic features.")

# Match
match_data = match_functions(features_a, features_b)
print(f"Matched {match_data['num_matches']} functions, "
      f"{match_data['num_unmatched_a']} unmatched in A, "
      f"{match_data['num_unmatched_b']} unmatched in B")

# Analyze
diff_data = analyze_diff(features_a, features_b, match_data)

# Triage
diff_data = triage_diff(diff_data)
print(f"Triage summary: {diff_data['triage_summary']}")

# Save diff
with open(os.path.join(outdir, "diff.json"), "w") as f:
    json.dump(diff_data, f, indent=2, default=str)

# Report
md = generate_markdown(diff_data)
with open(os.path.join(outdir, "report.md"), "w") as f:
    f.write(md)

html = generate_html(md)
with open(os.path.join(outdir, "report.html"), "w") as f:
    f.write(html)

print(f"\nOutputs written to {outdir}/")
print("  features_v1.json, features_v2.json")
print("  diff.json")
print("  report.md, report.html")
print("\nTop findings:")
for func in diff_data["functions"][:5]:
    label = func.get("triage_label", "?")
    interest = func.get("interestingness", 0)
    rationale = func.get("triage_rationale", [])
    print(f"  [{label}] {func['name_a']} (interest={interest})")
    for r in rationale:
        print(f"    - {r}")
