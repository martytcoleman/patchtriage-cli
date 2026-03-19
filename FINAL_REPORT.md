# PatchTriage: Adaptive Binary Patch Triage for Likely Security Fixes

## 1. Overview

The goal of this project was not to build another general-purpose binary differ. Tools such as BinDiff and Diaphora already cover that space well. Instead, I focused on a narrower question that is directly useful during patch analysis:

> After a patch lands, which changed functions deserve immediate reverse-engineering attention?

The result is `PatchTriage`, a command-line tool that compares two versions of a binary, matches functions or coarse regions across versions, computes change signals, and ranks the changes that are most likely to matter for security review.

The main design decision in the final version was to treat binary analysis as an adaptive problem rather than assuming that one extraction strategy works well for every target. Conventional native binaries can go through a richer Ghidra-backed pipeline. Harder binaries, especially large Go or Rust executables, can fall back to a lightweight path that still produces a usable coarse triage instead of failing outright.

## 2. Problem Statement

Binary diffing tools are useful, but they often optimize for broad correspondence rather than analyst triage. In practice, a patch analyst usually wants to answer a smaller question first: which parts of the update should be inspected before everything else?

That problem becomes harder when:

- the binary is stripped
- compiler settings change across versions
- language-specific runtime code dominates the binary
- heavyweight analysis tools become slow or noisy

I therefore scoped the project around patch triage, not full semantic recovery. The desired output is a ranked review queue with evidence, not an automatic vulnerability proof.

## 3. System Design

PatchTriage has four main stages:

1. extract features from each binary
2. match functions or coarse nodes across versions
3. analyze the change signals for each match
4. triage and rank the results for review

### 3.1 Adaptive Extraction

The extraction stage now supports multiple modes:

- `ghidra/full`: richer per-function extraction for smaller conventional binaries
- `ghidra/fast`: lighter-weight extraction for larger but still manageable binaries
- `light`: non-Ghidra extraction for difficult binaries where Ghidra is too slow or unreliable

The tool performs a cheap pre-scan before extraction. That pre-scan classifies the file format, checks for Go or Rust markers, estimates binary size, and chooses a backend/profile automatically unless the user overrides it.

This is the most important architectural change I made late in the project. Earlier versions implicitly assumed that Ghidra should always be the front end. In practice that made the tool brittle on some real targets. The adaptive version degrades more gracefully.

### 3.2 Feature Representation

On the rich path, PatchTriage extracts per-function features including:

- normalized referenced strings
- string categories such as `error`, `bounds`, `path`, and `format`
- external and internal calls
- API-family groupings
- constant buckets
- mnemonic histograms and coarse instruction groups
- basic CFG and size metrics

On the light path, the tool extracts coarser nodes instead of pretending to have real per-function fidelity. Those nodes include:

- a whole-binary summary node
- section-level nodes
- import-family nodes
- named text-symbol nodes when available
- cheap instruction summaries from disassembly

The light backend is intentionally coarse, but it is still useful because it preserves enough structure to answer broad triage questions.

### 3.3 Matching

Matching uses weighted multi-signal similarity rather than a single feature. Exact names are helpful when present, but stripped mode ignores names entirely and relies on structural and contextual features instead. Candidate pairs are solved with bipartite assignment rather than a greedy pass.

For stripped binaries, I also had to normalize away a major source of noise: auto-generated names such as `FUN_<addr>`. Earlier versions overcounted internal call churn simply because addresses changed between builds. The final analyzer canonicalizes internal calls through matched entries where possible, which significantly reduced false positives.

### 3.4 Triage Heuristics

The ranking logic is security-oriented rather than generic. Current heuristics look for:

- unsafe-to-safe API replacements
- added stack protection
- new bounds-style constants combined with new comparisons
- new error or validation strings
- growth in comparisons, branches, and basic blocks consistent with new guard logic

The output labels are:

- `security_fix_likely`
- `security_fix_possible`
- `behavior_change`
- `refactor`
- `unchanged`

That label set turned out to be a better fit than a generic “interesting/uninteresting” score because it makes the report much easier to scan.

## 4. CLI and Reproducibility

The project is usable as a CLI without custom scripts:

```bash
patchtriage run <old_binary> <new_binary> -o out
patchtriage extract <binary> -o features.json
patchtriage diff <features_a> <features_b> -o diff.json
patchtriage report <diff.json>
patchtriage evaluate examples/example_corpus.json
```

The `run` command performs the full pipeline and prints a report to the terminal while also writing JSON and Markdown artifacts. Intermediate feature files are cached and reused unless `--force` is passed.

## 5. Evaluation

I evaluated the tool in three different ways:

1. a small reproducible fixture corpus
2. a small open-source synthetic target with known security-style fixes
3. real release binaries, including one case that goes through the fallback path

### 5.1 Fixture Corpus

The fixture corpus is intentionally small, but it is useful for regression testing the core logic without running Ghidra. The current corpus result is:

- cases: `1`
- match recall: `1.0`
- top-3 security hit rate: `1.0`

This is not a substitute for real-world evaluation, but it was useful during development because it made the matching and triage layers easy to test repeatedly.

### 5.2 Open-Source Synthetic HTTP Server

This was the clearest success case. Using the checked-in feature files, PatchTriage produced:

- `8` matched functions
- `1` unmatched function in the old version
- `2` unmatched functions in the new version

The triage summary was:

- `3` `security_fix_likely`
- `3` `security_fix_possible`
- `1` `refactor`
- `1` `unchanged`

The top-ranked function was `_parse_http_request`, followed by `_parse_request_line` and `_url_decode`. This is the result I would point to as the strongest demonstration that the triage logic is doing the right kind of work. The report identifies exactly the kinds of changes that a human reviewer would care about: replacement of unsafe string APIs, new validation strings, and increased control flow associated with input checking.

Artifacts:

- [open-source report](/Users/marty/patchdiff-cli/final_artifacts/open_source/report.md)
- [open-source diff](/Users/marty/patchdiff-cli/final_artifacts/open_source/diff_triaged.json)

### 5.3 `jq` 1.7 to 1.7.1

I also tested the tool on official `jq` release binaries. This is a more realistic stripped-binary case than the synthetic server and therefore a better stress test for matching.

The result was:

- `1449` matched functions
- `1` unmatched function in the old version
- `0` unmatched functions in the new version

The triage summary was:

- `1` `security_fix_possible`
- `48` `behavior_change`
- `9` `refactor`
- `1391` `unchanged`

This result is mixed but still useful. The positive side is that the matching held up well even in stripped mode, and the report did isolate one candidate function worth immediate review. The limitation is that the top function remained anonymous (`FUN_...`), so the tool could say “look here first” more confidently than it could say exactly what vulnerability was fixed.

That is still a valuable outcome for patch triage. It narrows the analyst’s search surface. But it is weaker than the synthetic case in terms of semantic clarity.

Artifact:

- [jq report](/Users/marty/patchdiff-cli/final_artifacts/jq/report.md)

### 5.4 `yq` 4.48.2 to 4.49.1

This case mattered for a different reason. `yq` is a Go binary, and it exposed the limitations of treating Ghidra as the only extraction path. Earlier in the project, the Ghidra-based workflow on this target was slow and noisy enough that it was not practically useful.

With the adaptive backend in place, `patchtriage run` chose the `light` backend automatically and produced a coarse but fast result:

- `23` matched coarse nodes
- `0` unmatched nodes

The triage summary was:

- `3` `behavior_change`
- `1` `refactor`
- `19` `unchanged`

The top items were section-level and whole-binary nodes rather than individual functions. That is clearly lower fidelity, but it still answers a useful question: did major code or metadata regions change in a way that justifies further manual inspection? In this sense, the fallback path succeeded. It did not recover fine semantics, but it did avoid a failed or misleading run.

Artifact:

- [yq report](/Users/marty/patchdiff-cli/final_artifacts/yq/report.md)

## 6. Discussion

The most important lesson from this project is that reliability matters as much as sophistication. A patch triage tool that works beautifully on one binary family but stalls or fails on another is hard to trust in practice. Moving to an adaptive design improved the tool more than adding another isolated heuristic would have.

The current system is strongest when:

- the target is a conventional native binary
- function structure is recoverable
- the patch introduces clear validation or memory-safety signals

It is weaker when:

- the binary is heavily runtime-dominated, as in large Go or Rust executables
- the patch is small and semantically subtle
- the code is stripped and the changed function remains anonymous after matching

Even in those weaker cases, the tool is now more reliable than earlier versions because it can fall back to a coarser but honest analysis instead of forcing a broken rich pipeline.

## 7. Limitations

This project does not beat mature diffing tools at general-purpose binary correspondence, and I do not claim that it does. Its contribution is narrower: triage and prioritization for security-oriented patch review.

The current limitations are:

- evaluation breadth is still modest
- the light backend is useful but coarse
- the rich path still depends heavily on Ghidra for full-fidelity extraction
- anonymous stripped functions remain difficult to explain semantically

I also did not complete a rigorous head-to-head benchmark against BinDiff or Diaphora. The more defensible claim is that PatchTriage emphasizes a different objective: ranking likely security-relevant changes for review.

## 8. Conclusion

PatchTriage ended up as a practical binary patch triage CLI rather than a full binary diff framework. I think that was the right scope. The final system can:

- extract and compare rich per-function features on friendlier binaries
- match stripped binaries reasonably well
- surface likely security-relevant changes with evidence-backed explanations
- adapt to harder binaries by switching to a lightweight fallback path

The strongest evidence is the open-source server case, where the review queue aligns well with known security-style fixes. The `jq` case shows that the matching and triage still provide value on a realistic stripped binary, although the semantic explanation is less precise. The `yq` case shows that the adaptive fallback path improves reliability on difficult targets.

In short, the project succeeded at the problem it was scoped to solve: helping an analyst decide what to reverse first after a patch lands.

## Appendix: Reproduction Commands

```bash
pytest -q
python -m patchtriage.cli evaluate examples/example_corpus.json
python -m patchtriage.cli diff targets/open_source/features_v1.json targets/open_source/features_v2.json -o final_artifacts/open_source/diff.json
python -m patchtriage.cli report final_artifacts/open_source/diff.json -o final_artifacts/open_source/report.md
python -m patchtriage.cli run corpus/jq/jq-1.7-macos-arm64 corpus/jq/jq-1.7.1-macos-arm64 -o final_artifacts/jq --stripped
python -m patchtriage.cli run corpus/yq/yq-v4.48.2-darwin-arm64 corpus/yq/yq-v4.49.1-darwin-arm64 -o final_artifacts/yq --backend auto --stripped
```
