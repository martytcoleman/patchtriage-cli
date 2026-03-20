# PatchTriage — Binary Security Patch Triage CLI

A command-line tool that answers one question quickly:

> After a patch lands, which changed functions deserve immediate reverse-engineering attention?

PatchTriage compares two versions of a binary, matches functions across versions, and produces a ranked security triage queue with evidence-backed rationale. It does not try to replace general-purpose binary diff engines — it focuses on the step after "here are 500 changed functions": deciding which 20 to read first for security patches.

Demo Video: https://drive.google.com/file/d/1CR4U5G37NhrmVKooBy4Aw_cVsVQYJIw7/view?usp=sharing

## Architecture

```
Binary A ──> [Adaptive Extraction] ──> features_A.json ─┐
                                                         ├──> match + analyze ──> triage ──> report
Binary B ──> [Adaptive Extraction] ──> features_B.json ─┘
```

Three extraction backends are selected automatically based on binary characteristics:

| Backend | When Used | What It Extracts |
|---------|-----------|-----------------|
| **native** | Symbolized C/C++ binaries | Per-function disassembly via nm/objdump: mnemonics, calls, strings, constants |
| **light** | Go/Rust binaries, large binaries (>8MB) | Whole-binary features, section analysis, import families. Go: full pclntab parsing |
| **ghidra** | Stripped binaries, fallback | Ghidra headless analysis with recovered function boundaries |

## Triage Labels

Each matched function receives a triage label based on security-relevant heuristics:

| Label | What Triggers It |
|-------|-----------------|
| `security_fix_likely` | Unsafe API swaps (strcpy→strncpy), stack protection added, multiple converging signals |
| `security_fix_possible` | Bounds constants + new comparisons, error/validation strings, guard logic |
| `behavior_change` | Meaningful structural or call-flow change without direct security evidence |
| `refactor` | Large structural change without semantic evidence |
| `unchanged` | No significant changes detected |

Every label comes with a list of rationale strings explaining exactly why it was assigned.

## Requirements

- **Python 3.10+**
- **Ghidra** (only needed for stripped binaries) — set `GHIDRA_INSTALL_DIR` env var
- **numpy**, **scipy** (installed automatically)
- Standard command-line tools: `nm`, `objdump`, `otool` (included on macOS with Xcode CLI tools)
- (Optional) **openai** package for LLM explanations: `pip install patchtriage[llm]`

## Installation

```bash
git clone <repo-url>
cd patchdiff-cli
pip install -e .
```

## Quick Start

```bash
# End-to-end triage (backend auto-selected)
patchtriage run old.bin new.bin -o out

# With HTML report
patchtriage run old.bin new.bin -o out --html

# Force a specific backend
patchtriage run old.bin new.bin -o out --backend native
patchtriage run old.bin new.bin -o out --backend ghidra
patchtriage run old.bin new.bin -o out --backend light
```

## Corpus Setup

A script populates the `corpus/` directory with ready-to-run version pairs:

```bash
scripts/download_corpus_targets.sh
```

This downloads and/or builds:

- **jq** 1.7 → 1.7.1 (pre-built release binaries)
- **yq** v4.48.2 → v4.49.1 (pre-built release binaries)
- **OpenSSL** 3.0.13 → 3.0.14 (built from source)
- **OpenSSH** 9.7p1 → 9.8p1 (built from source)

Then run PatchTriage on those binaries:

```bash
patchtriage run corpus/openssl/openssl-3.0.13-darwin-arm64 corpus/openssl/openssl-3.0.14-darwin-arm64 -o corpus/openssl/results
patchtriage run corpus/openssh/sshd-9.7p1-darwin-arm64 corpus/openssh/sshd-9.8p1-darwin-arm64 -o corpus/openssh/results
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `patchtriage run <bin_a> <bin_b>` | Full pipeline: extract → match → triage → report |
| `patchtriage extract <bin>` | Extract features from a single binary |
| `patchtriage diff <feat_a> <feat_b>` | Match and analyze from saved feature JSONs |
| `patchtriage report <diff.json>` | Regenerate triage/report from saved diff |
| `patchtriage evaluate <corpus.json>` | Run fixture-based evaluation |

### Key Options

```bash
--backend auto|native|ghidra|light   # Extraction backend (default: auto)
--stripped                            # Ignore function names, match by structure only
--html                                # Generate HTML report
--top N                               # Show top N functions (default: 30)
--force                               # Re-extract even if cached features exist
--llm                                 # Add LLM-generated analysis (requires API key in .env)
--provider openai|grok                # LLM provider (auto-detected if not set)
```

## Matching Algorithm

Functions are matched in three passes:

1. **Pass 1 — Exact name matching.** Non-auto-generated names matched directly. Duplicate names (common in OpenSSL) resolved by best similarity score.

2. **Pass 1.5 — Name-exclusion with rename detection.** Named functions absent from the other binary are checked for plausible renames (case changes, suffix additions, substring matches) before being excluded from the similarity pass.

3. **Pass 2 — Bipartite similarity assignment.** Remaining functions compared using a 14-signal weighted similarity score (name, strings, calls, mnemonics, instruction groups, bigrams, API families, roles, constants, callgraph context, size, blocks). Candidates filtered by 3x size ratio. Solved with `scipy.optimize.linear_sum_assignment`. Close alternatives flagged as "uncertain."

## Triage Heuristics

| Heuristic | What It Detects |
|-----------|----------------|
| Unsafe API swap | `strcpy`→`strncpy`, `sprintf`→`snprintf`, etc. |
| Stack protection | New `__stack_chk_fail` / `__fortify_fail` calls |
| Bounds constants + checks | Power-of-2 constants with new comparisons in security context |
| Error strings | New strings containing "error", "overflow", "invalid", etc. |
| Validation paths | Simultaneous block + compare + branch growth with semantic evidence |
| Extract-and-harden | Function shrinks + related new function appears in B |

## Evaluated Targets

| Target | Backend | Matched | SEC-LIKELY | SEC-POSSIBLE | Known CVEs Found |
|--------|---------|---------|------------|--------------|-----------------|
| OpenSSL 3.0.13→14 | native | 12,028 | 2 | 1 | 3/3 |
| OpenSSH 9.7→9.8 | native | 681 | 3 | 3 | 1/1 (+ structural) |
| SQLite 3.51.2→3 | ghidra | 2,356 | 2 | 0 | corruption detection |
| zstd 1.5.5→7 | native | 1,132 | 0 | 3 | stack hardening |
| jq 1.7→1.7.1 | ghidra | 1,449 | 0 | 1 | stack hardening |
| yq 4.48→4.49 | light | 11,154 | 0 | 0 | minor release (correct) |
| test binaries | native | 10 | 4 | 3 | synthetic (7/7) |

See `FINAL_REPORT.md` for detailed evaluation with CVE cross-referencing, baseline comparison, and per-target analysis.

## Output Files

| File | Description |
|------|-------------|
| `*_features.json` | Per-function feature vectors for a binary |
| `diff.json` | Matched functions with change signals and interestingness scores |
| `report.json` | Diff data enriched with triage labels and rationale |
| `report.md` | Human-readable ranked report |
| `report.html` | HTML version of the report |

## Project Structure

```
patchdiff-cli/
├── FINAL_REPORT.md                    # Full project report with evaluation
├── README.md
├── pyproject.toml
├── ghidra_scripts/
│   └── extract_features.py            # Ghidra Jython script for feature extraction
├── patchtriage/
│   ├── cli.py                         # CLI entry point and pipeline orchestration
│   ├── classify.py                    # Binary pre-scan classification
│   ├── extract.py                     # Ghidra headless runner
│   ├── native.py                      # Native extraction (nm + objdump)
│   ├── light.py                       # Light extraction (Go pclntab, sections, imports)
│   ├── normalize.py                   # Feature enrichment (string categories, API families, roles)
│   ├── matcher.py                     # Three-pass function matching
│   ├── analyzer.py                    # Change signal computation + interestingness scoring
│   ├── triage.py                      # Security-focused triage heuristics
│   ├── report.py                      # Markdown/HTML report generation
│   ├── console.py                     # Colorized terminal output
│   ├── llm_explain.py                 # Optional LLM summary generation
│   └── evaluate.py                    # Fixture-based evaluation
├── tests/                             # 54 unit/integration tests
│   ├── test_matcher.py
│   ├── test_triage.py                 # 510 lines — core heuristic coverage
│   ├── test_normalize.py
│   ├── test_report.py
│   ├── test_native.py
│   └── ...
├── corpus/                            # Evaluation targets (populated by setup script)
└── scripts/
    └── download_corpus_targets.sh     # One-command corpus setup
```

## Running Tests

```bash
pip install -e ".[dev]"
pytest tests/ -v    # 54 tests, ~1s
```

## License

MIT
