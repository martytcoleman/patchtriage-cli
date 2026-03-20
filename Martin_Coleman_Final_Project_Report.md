# PatchTriage: Adaptive Binary Patch Triage for Likely Security Fixes

**Martin Coleman - Reverse Engineering Basics Final Project - March 20, 2026**

GitHub Repository URL: https://github.com/martytcoleman/patchtriage-cli

Demo Video: https://drive.google.com/file/d/1CR4U5G37NhrmVKooBy4Aw_cVsVQYJIw7/view?usp=sharing

## 1. Overview

Binary diff tools such as BinDiff and Diaphora are good at telling an analyst which functions changed between two versions of a binary. In practice, though, that's often not the hardest part of patch analysis. Once a diff produces hundreds of changed functions, the real problem becomes deciding which ones are most worth inspecting first.

PatchTriage is aimed at that triage step. The question I wanted to answer was: after a patch lands, which changed functions should a reverse engineer inspect first? Rather than presenting a full diff for the analyst to explore manually, it attempts to rank the changed functions by how likely they are to matter for security review and to explain why each one was flagged.

The implementation is a command-line tool that compares two versions of a binary, matches functions across versions, computes change signals, and produces a ranked review queue. Each function receives a triage label (`security_fix_likely`, `security_fix_possible`, `behavior_change`, `refactor`, or `unchanged`) along with rationale based on the extracted signals.

The main design decision in the final version was to treat binary analysis as an adaptive problem rather than assuming that one extraction strategy works for every target. Symbolized C/C++ binaries go through a fast native extraction path. Harder binaries — especially large Go or Rust executables — fall back to a lightweight path that still produces a coarse but useful triage instead of failing outright. Stripped binaries can go through Ghidra for richer structural recovery.

## 2. Problem statement and related work

Binary diffing tools are useful, but they tend to optimize for broad function correspondence rather than analyst triage. In real environments, a patch analyst / reverse engineer usually wants to answer a smaller question first: which parts of the update should be inspected before everything else?

That problem becomes harder when:

- the binary is stripped
- compiler settings change across versions
- language-specific runtime code dominates the binary
- heavyweight analysis tools become slow or noisy

I deliberately scoped the project around triage rather than full vulnerability discovery. I ultimately wanted to help an analyst decide what to inspect first instead of proving automatically that a vulnerability exists.

### Related work

BinDiff (Google/Zynamics) is the standard for binary function matching. It uses a multi-pass algorithm (name matching, hash matching, call graph propagation) to produce a function correspondence. Diaphora (Joxean Koret) is an open-source IDA Pro plugin with a similar approach and some vulnerability-related heuristics of its own. Both tools are primarily designed around exhaustive diff exploration — the analyst browses the full correspondence and applies judgment to each entry. DarunGrim and TurboDiff are older tools in the same space.

PatchTriage is aimed at a narrower problem. Where BinDiff and Diaphora optimize for correspondence exploration — giving the analyst a complete map of what changed — PatchTriage optimizes for analyst attention: which changes should be reviewed first, and why. Its contribution is a combination of prioritization with per-function rationale and adaptive extraction that handles different binary types without manual configuration. The adaptive backend selection (Ghidra, native, light) came out of practical debugging — a single analysis path worked poorly across the full corpus, so I changed the design to choose different extraction strategies for different kinds of binaries.

## 3. System design

PatchTriage has four main stages:

```
Binary A ──> [Adaptive Extraction] ──> features_A.json ─┐
                                                         ├──> match + analyze ──> triage ──> report
Binary B ──> [Adaptive Extraction] ──> features_B.json ─┘
```

1. extract features from each binary
2. match functions or coarse nodes across versions
3. analyze the change signals for each match
4. triage and rank the results for review

### 3.1 Adaptive extraction

The extraction stage supports three backends, selected automatically based on binary characteristics:

| Backend | When Used | What It Extracts |
|---------|-----------|-----------------|
| native | Symbolized C/C++ binaries (nm finds symbols) | Per-function disassembly, mnemonics, call targets, strings, constants |
| light | Go/Rust binaries, large binaries (>8MB) | Whole-binary features, section-level analysis, import families. For Go: full pclntab parsing |
| ghidra | Stripped binaries (no symbols), fallback | Full decompiler analysis with recovered function boundaries |

The tool performs a cheap pre-scan before extraction. That pre-scan classifies the file format, checks for Go or Rust markers, estimates binary size, and chooses a backend automatically unless the user overrides it.

This ended up being the most important architectural change I made. Earlier versions assumed that Ghidra should always be the front end. When I ran it on real targets, that made the tool brittle — yq was the worst case, where Ghidra's Go analysis was slow and noisy. Once I made backend selection adaptive, the tool became much more reliable across the full corpus.

#### Ghidra script (ghidra_scripts/extract_features.py)

The Ghidra backend uses a Jython script that runs inside Ghidra's headless analyzer. The script iterates over all non-thunk functions and extracts, for each one:

- Mnemonic histogram and bigrams — instruction frequency distribution and consecutive instruction pairs, collected by walking the listing's instruction iterator over the function body
- Referenced strings — found by following references from each instruction to data addresses, checking `hasStringValue()` on the target. This per-instruction walk is intentional: the naive approach of scanning the global reference iterator from the function's start address turned out to be prohibitively slow on larger binaries.
- Called functions — both external imports and internal calls, with an `is_external` flag derived from `isExternal() or isThunk()`
- Constants — scalar operand values extracted from instruction operands via `getOpObjects()`, filtered to the range 2..0xFFFFFFFF to exclude trivial 0/1 values
- CFG metrics — basic block count (from `BasicBlockModel`), instruction count, and function body size
- Caller list — which functions call this one, used later for callgraph context in matching

#### Native backend (patchtriage/native.py)

The native backend avoids Ghidra entirely by reconstructing function-level features from `nm` (text symbols) and `objdump` (disassembly). For each function, it parses the disassembly to extract mnemonic histograms, identifies call targets through `bl`/`call` instructions and stub resolution, extracts literal-pool strings and immediate constants, and computes block counts from branch targets. It's less precise than Ghidra on stripped binaries, but it is fast (~2 seconds for 12,000 functions in OpenSSL) and fully deterministic.

### 3.2 Feature representation

On the rich path (native or Ghidra), PatchTriage extracts per-function features including normalized referenced strings, string categories (error, bounds, path, format), external and internal calls, API-family groupings, constant buckets, mnemonic histograms and coarse instruction groups, and basic CFG and size metrics.

On the light path, the tool extracts coarser nodes instead of pretending to have real per-function fidelity. These include a whole-binary summary node, section-level nodes, import-family nodes, named text-symbol nodes when available, Go pclntab-derived function entries with real names and sizes, and cheap instruction summaries from disassembly.

The light backend is definitely coarser. That said, it still turned out to be strong enough to tell whether a release looked broadly security-relevant or mostly routine.

### 3.3 Matching

Matching runs in three passes, plus a small post-pass repair:

Pass 1 — Exact name matching. Functions with non-auto-generated names (i.e., not `FUN_<addr>`) are matched by exact name. When multiple functions in the target binary share the same name (common in OpenSSL, where symbols like `_update` or `_rsa_settable_ctx_params` appear in different compilation units), the matcher picks the best candidate by similarity score rather than skipping the match entirely.

Pass 1.5 — Name-exclusion with rename detection. Named functions that are absent from the other binary are checked for plausible renames before being excluded from the similarity pass. This catches cases like `_badusage` to `_badUsage` (case change), `_BMK_benchCLevel` to `_BMK_benchCLevels` (suffix addition), and `_ZSTD_compressBlock_fast` to `_ZSTD_compressBlock_fast_noDict` (specialization). Without this step, the OpenSSH sshd-to-sshd-session split produced dozens of false matches: 535 functions removed from sshd were force-paired by similarity with unrelated new functions, causing 5 of 10 security-flagged functions to be mismatched.

Pass 2 — Similarity-based bipartite assignment. Remaining functions are compared using a weighted multi-signal similarity score:

| Signal | Weight | Method |
|--------|--------|--------|
| Name similarity | 0.15 | Normalized Levenshtein (0 in stripped mode) |
| Mnemonic histogram | 0.14 | Cosine similarity |
| Normalized strings | 0.12 | Jaccard similarity |
| External calls | 0.10 | Jaccard similarity |
| String categories | 0.08 | Jaccard similarity |
| All calls | 0.08 | Jaccard similarity |
| Instruction groups | 0.08 | Cosine similarity |
| Function roles | 0.06 | Jaccard similarity |
| Mnemonic bigrams | 0.05 | Jaccard on bigram sets |
| API families | 0.05 | Jaccard similarity |
| Callgraph context | 0.05 | Ratio similarity |
| Constant buckets | 0.04 | Jaccard similarity |
| Size penalty | 0.025 | min/max ratio |
| Block similarity | 0.025 | min/max ratio |

Candidate pairs are filtered by a 3x size ratio blocking step, then solved with bipartite assignment (scipy's `linear_sum_assignment`) rather than a greedy pass. Matches where the top alternatives are within 0.05 of the winning score are flagged as "uncertain."

In symbolized builds, I also added a cross-name similarity floor during Pass 2. If both sides have real symbol names and those names are not plausible renames, the pair must meet a higher similarity threshold (0.52) in order to be considered. This blocks many implausible pairings between unrelated APIs that would otherwise clear the default threshold due to superficial similarity in small wrappers.

After bipartite assignment, I apply a short repair pass for a specific case: global assignment can sometimes pair a function in A with an unrelated function in B even while a same-named function in B remains unmatched. When that situation is unambiguous, the matcher re-points the pair to the unmatched same-name symbol. This fixed several inconsistent OpenSSL rows in which a symbol was simultaneously mismatched and listed as new in B.

For stripped binaries, I also had to normalize away a major source of noise: auto-generated names like `FUN_<addr>`. Earlier versions overcounted internal call churn simply because addresses changed between builds. The final analyzer canonicalizes internal calls through matched entries where possible, which made a significant difference in false positive rates.

### 3.4 Triage heuristics

The ranking logic is focused on security-relevant patterns rather than generic change magnitude. Current heuristics look for:

- unsafe-to-safe API replacements (strcpy to strncpy, sprintf to snprintf, etc.)
- added stack protection (`__stack_chk_fail`, `__fortify_fail`)
- new bounds-style constants combined with new comparisons
- new error or validation strings
- growth in comparisons, branches, and basic blocks consistent with new guard logic
- extract-and-harden patterns (function shrinks significantly and a related new function appears)

Each function receives one of five labels: `security_fix_likely`, `security_fix_possible`, `behavior_change`, `refactor`, or `unchanged`. I found this label set more useful than a single "interestingness" score because it tells the analyst not just where to look, but what kind of change to expect when they get there.

## 4. Setup and usage

### 4.1 Requirements

- Python 3.10+
- Ghidra (only needed for stripped binaries) — set `GHIDRA_INSTALL_DIR` env var or install to `~/ghidra_*/`
- numpy, scipy (installed automatically)
- Standard command-line tools: `nm`, `objdump`, `otool` (included on macOS with Xcode CLI tools)
- (Optional) openai package for LLM explanations: `pip install patchtriage[llm]`

### 4.2 Installation

```bash
git clone https://github.com/martytcoleman/patchtriage-cli
cd patchtriage-cli
pip install -e .
```

### 4.3 Corpus setup

The corpus binaries are not checked into git directly. A setup script downloads pre-built binaries (jq, yq) and builds the others (OpenSSL, OpenSSH) from source:

```bash
scripts/download_corpus_targets.sh
```

The script detects OS and architecture automatically. Building OpenSSL and OpenSSH from source takes several minutes. The synthetic test binaries (`corpus/open_source/server_v1`, `server_v2`) are the only ones included in the repository directly.

SQLite and zstd require additional steps — see the reproduction commands in sections 5.5 and 5.6 below.

### 4.4 CLI

The implementation is exposed through a command-line interface with the following subcommands:

```bash
patchtriage run <old_binary> <new_binary> -o out
patchtriage extract <binary> -o features.json
patchtriage diff <features_a> <features_b> -o diff.json
patchtriage report <diff.json>
patchtriage evaluate examples/example_corpus.json
```

The `run` command performs the full pipeline and prints a report to the terminal while also writing JSON and Markdown artifacts. Intermediate feature files are cached and reused unless `--force` is passed.

### 4.5 Additional options

```bash
# Force re-extraction (ignore cache)
patchtriage run binary_a binary_b --force

# Override backend selection
patchtriage run binary_a binary_b --backend native
patchtriage run binary_a binary_b --backend light
patchtriage run binary_a binary_b --backend ghidra

# Generate HTML report
patchtriage run binary_a binary_b --html

# Show more functions in terminal output
patchtriage run binary_a binary_b --top 50

# Enable LLM-assisted analysis (requires API key in .env)
patchtriage run binary_a binary_b --llm --provider grok
```

## 5. Evaluation

I evaluated the tool across seven corpus targets spanning different binary formats, languages, sizes, and known security fix profiles.

### 5.1 Evaluation methodology

For targets with published CVEs (OpenSSL 3.0.14, OpenSSH 9.8), I used the official security advisories to identify which functions should appear in the triage output. "CVE alignment" means that the advisory's described behavior (e.g., "excessively long DSA keys") maps to a ranked or unmatched function whose name and change signals are consistent with that description. This mapping is necessarily manual judgment — the advisories describe APIs and behavior, not specific symbol names, so I cross-referenced advisory text with the tool's output to determine whether the right area of the binary was surfaced.

"Label correct" means the triage label assigned to a CVE-aligned function is appropriate: a function implementing a security fix should receive `security_fix_likely` or `security_fix_possible`, not `refactor` or `unchanged`. Match accuracy was verified by manual inspection of cross-name pairings — checking that any function matched to a differently-named counterpart was a plausible rename rather than a coincidental structural match.

For targets without known CVEs (zstd, jq, yq), evaluation focused on whether the label distribution was reasonable given the nature of the release. A minor bugfix release should not produce dozens of SEC-LIKELY flags, and a release with known hardening changes should surface those changes near the top.

### 5.2 Results summary

| Target | Backend | Matched | SEC-LIKELY | SEC-POSSIBLE | Known CVEs Found |
|--------|---------|---------|------------|--------------|-----------------|
| OpenSSL 3.0.13→14 | native | 12,028 | 2 | 1 | 3/3 |
| OpenSSH 9.7→9.8 | native | 681 | 3 | 3 | 1/1 (+ structural) |
| SQLite 3.51.2→3 | ghidra | 2,356 | 2 | 0 | corruption detection |
| zstd 1.5.5→7 | native | 1,132 | 0 | 3 | stack hardening |
| jq 1.7→1.7.1 | ghidra | 1,449 | 0 | 1 | stack hardening |
| yq 4.48→4.49 | light | 11,154 | 0 | 0 | minor release (correct) |
| test binaries | native | 10 | 4 | 3 | synthetic (7/7) |

### 5.3 OpenSSL 3.0.13 → 3.0.14 (CVE validation)

OpenSSL **3.0.14** was released **4 June 2024** with fixes for **three** CVEs, as summarized in the [OpenSSL 3.0 series release notes](https://www.openssl.org/news/openssl-3.0-notes.html) (and `CHANGES.md` in the source tree). This is the clearest evaluation case because those advisories are explicit and the patch is contained in one library pair.

Top security findings:

| Rank | Function | Label | Key Signal |
|------|----------|-------|------------|
| #1 | `_EVP_PKEY_CTX_add1_hkdf_info` | SEC-LIKELY | Stack protection added, +1712.5% |
| #2 | `_ossl_dsa_check_pairwise` | SEC-POSSIBLE | New guard logic, +81.8% |
| #3 | `_EVP_Update_loop` | SEC-LIKELY | Stack protection added, bounds constant +24.4% |

The tool also surfaces **12** new functions in B (unmatched), e.g. `_ssl_session_dup_intern`, `_dsa_precheck_params`, and `_kdf_hkdf_gettable_ctx_params`. Mapping individual symbols to a specific CVE is necessarily an inference from the binary diff, since the advisories usually describe affected behavior or APIs rather than naming every changed internal symbol. Some unmatched symbols are collateral changes in the same release rather than called out line-by-line in the security notice.

**CVE-2024-4741** — Official summary: *potential use-after-free after `SSL_free_buffers()` is called* (low severity; advisory notes this API is **rarely used**). This is **not** the same issue as TLSv1.3 session-cache growth (CVE-2024-2511). A binary-level report may show libssl/record-path churn without a literal `SSL_free_buffers` symbol jumping out of the ranking.

**CVE-2024-4603** — Official summary: *checking excessively long DSA keys or parameters may be very slow*. Aligns well with triage: `_ossl_dsa_check_pairwise` at the top with SEC-POSSIBLE and growth in comparison/branch structure, plus `_dsa_precheck_params` as new in B.

**CVE-2024-2511** — Official summary: *unbounded memory growth with session handling in TLSv1.3*. Aligns with refactors around session duplication: `_ssl_session_dup_intern` as new in B and `_ssl_session_dup` often shrinking with “extract-and-harden” style rationale in the report.

**Same release, not separate CVEs:** Strong signals on other symbols (e.g. `_EVP_PKEY_CTX_add1_hkdf_info` with stack protection and +1712% growth at SEC-LIKELY #1, or `_EVP_Update_loop` with stack protection and bounds constants) can reflect **hardening shipped in 3.0.14** without being additional named CVEs in that advisory set—the published security fixes for this bump are the **three** CVEs above.

Across this case study, the themes of all three advisories (buffers/session/DSA) show up somewhere in the ranked or unmatched output, which suggests the triage layer is useful for steering review—while **symbol-to-CVE attribution** should stay grounded in the official text.

Reproduction:
```bash
patchtriage run \
    corpus/openssl/openssl-3.0.13-darwin-arm64 \
    corpus/openssl/openssl-3.0.14-darwin-arm64 \
    -o corpus/openssl/results
```

### 5.4 OpenSSH 9.7p1 → 9.8p1 (CVE-2024-6387 "regreSSHion")

OpenSSH 9.8p1 was released July 2024 to fix CVE-2024-6387, a critical unauthenticated RCE vulnerability in sshd's SIGALRM signal handler. This release also rearchitected sshd by splitting it into a listener process (`sshd`) and a per-session process (`sshd-session`), which reduced the sshd binary from 994KB to 578KB.

Triage results: 681 matched, 561 removed from A, 26 new in B.

| Label | Count |
|-------|-------|
| SEC-LIKELY | 3 |
| SEC-POSSIBLE | 3 |
| BEHAVIOR | 9 |
| REFACTOR | 8 |
| UNCHANGED | 658 |

Top security findings:

| Rank | Function | Label | Key Signal |
|------|----------|-------|------------|
| #1 | `_server_accept_loop` | SEC-POSSIBLE | +42.6%, +50 blocks, +27 comparisons |
| #2 | `_process_server_config_line_depth` | SEC-LIKELY | Bounds constants, +29 blocks, parser logic |
| #3 | `_main` | SEC-POSSIBLE | Bounds constants, new `socketpair`/`snprintf` |
| #4 | `_send_rexec_state` | SEC-LIKELY | Stack protection, bounds constants, +141.7% |
| #5 | `_permitopen_port` | SEC-LIKELY | Stack protection, bounds constants |

CVE-2024-6387 alignment:

- `_server_accept_loop` (ranked #1) — the core server loop was rearchitected to move child process management and signal handling into a safe unprivileged listener. The +42.6% size increase with 50 new blocks reflects the new process orchestration code that replaces the vulnerable signal handler approach.

- `_grace_alarm_handler` removed — appears in the 561 "Unmatched in A" functions. This was the async-signal-unsafe handler that caused CVE-2024-6387. Its complete removal is the most direct evidence of the fix.

- `_main_sigchld_handler` shrunk 84% (ranked #11 as REFACTOR) — the SIGCHLD handler was stripped to bare signal-safe operations (set a flag and return), eliminating the race condition attack surface.

- `_privsep_preauth` removed — pre-authentication privilege separation was rearchitected as part of the sshd split.

- 561 functions removed, 26 new — the sshd binary shrank from 994KB to 578KB because per-session functionality was moved to the new `sshd-session` binary. The tool reports these as unmatched rather than forcing spurious matches. The 26 new functions include the new penalty/rate-limiting system (`_srclimit_penalise`, `_srclimit_penalty_check_allow`, `_expire_penalties`) and new safe signal handlers (`_siginfo_handler`, `_signal_is_crash`).

Reproduction:
```bash
patchtriage run \
    corpus/openssh/sshd-9.7p1-darwin-arm64 \
    corpus/openssh/sshd-9.8p1-darwin-arm64 \
    -o corpus/openssh/results
```

### 5.5 SQLite 3.51.2 → 3.51.3

SQLite distributes pre-built stripped binaries with no debug symbols — from a reverse engineering perspective, this is effectively a closed-source target. The tool uses the Ghidra backend to recover function boundaries. Function names remain anonymous (`FUN_<addr>`), but the triage logic still works based on the extracted signals.

| Rank | Function | Label | Key Signal |
|------|----------|-------|------------|
| #1 | `FUN_100013080` | SEC-LIKELY | Error/validation strings: `"database corruption"` |
| #2 | `FUN_10004a32c` | SEC-LIKELY | Added `"database corruption"` string, +22.3% |

The functions flagged here have new corruption detection and error handling, which the triage heuristics rank as top priority for review. Without function names, the tool cannot explain what these functions do, but it can point the analyst to the right addresses. Note that Ghidra's function boundary recovery on stripped binaries is slightly nondeterministic — repeated runs may produce small variations in matched counts and labels (typically ±1).

Reproduction:
```bash
cd corpus/sqlite
unzip -o sqlite-tools-osx-arm64-3510200.zip -d v3510200
unzip -o sqlite-tools-osx-arm64-3510300.zip -d v3510300
cd ../..

patchtriage run \
    corpus/sqlite/v3510200/sqlite3 \
    corpus/sqlite/v3510300/sqlite3 \
    -o corpus/sqlite/results \
    --backend ghidra
```

### 5.6 Zstandard (zstd) 1.5.5 → 1.5.7

Zstd is a compression library where most changes are performance and algorithm optimizations. This tests whether the tool can separate security-relevant changes from codec churn.

| Rank | Function | Label | Key Signal |
|------|----------|-------|------------|
| #1 | `_ZSTD_compressBlock_doubleFast` | SEC-POSSIBLE | Stack protection added |
| #2 | `_ZSTDMT_freeCCtx` | SEC-POSSIBLE | Stack protection added |
| #3 | `_ZSTD_compressSeqStore_singleBlock` | SEC-POSSIBLE | Bounds constants + comparisons |

On this target, the tool flags only 3 functions as plausibly security-relevant (stack hardening, bounds checking) while classifying the remaining 89 behavioral changes as codec-oriented. Getting here required several rounds of noise reduction:
- Codec role detection that caps interestingness of codec-only functions without semantic evidence
- Address constant filtering (values > 0x100000000 are pointer artifacts, not real constants)
- Phantom churn detection for data tables misinterpreted as code

Reproduction:
```bash
cd corpus/zstd && tar xzf zstd-1.5.5.tar.gz && tar xzf zstd-1.5.7.tar.gz && cd ../..
cd corpus/zstd/zstd-1.5.5 && make -j && cd ../../..
cd corpus/zstd/zstd-1.5.7 && make -j && cd ../../..

patchtriage run \
    corpus/zstd/zstd-1.5.5/programs/zstd \
    corpus/zstd/zstd-1.5.7/programs/zstd \
    -o corpus/zstd/results
```

### 5.7 jq 1.7 → 1.7.1

jq 1.7 to 1.7.1 was a bugfix release. The binary is stripped, requiring the Ghidra backend.

The tool flags only 1 security-relevant change (stack protection added) and ranks it appropriately, with 1,425 of 1,449 functions classified as unchanged.

One issue I ran into here: jq's embedded stdlib string (~5,000 characters) contains the keyword "error" as a jq language construct, not as an error-handling indicator. This was triggering false positives until I added a filter that skips strings longer than 500 characters from error-keyword matching.

Reproduction:
```bash
patchtriage run \
    corpus/jq/jq-1.7-macos-arm64 \
    corpus/jq/jq-1.7.1-macos-arm64 \
    -o corpus/jq/results \
    --backend ghidra
```

### 5.8 yq v4.48.2 → v4.49.1

yq is a 10MB Go binary. Standard `nm` returns 0 text symbols for Go binaries because Go uses its own symbol table format. This was one of the harder cases to get working. The tool handles it through:

1. Go detection: checks for `__gopclntab` Mach-O section when byte-prefix markers fall outside the 2MB pre-scan window
2. pclntab parsing: a full Go PC line table parser supporting Go 1.16+ format, which extracts 11,154 function names and sizes directly from the binary's embedded metadata

This result is consistent with the release: it was a minor update with no obvious security-relevant changes, and the tool reports 0 SEC-LIKELY and 0 SEC-POSSIBLE. Earlier versions of the tool showed only 23 "functions" — all section/import nodes — because they lacked Go-specific extraction.

Reproduction:
```bash
patchtriage run \
    corpus/yq/yq-v4.48.2-darwin-arm64 \
    corpus/yq/yq-v4.49.1-darwin-arm64 \
    -o corpus/yq/results
```

### 5.9 Triage quality: precision and baseline comparison

The main argument for the triage layer is that it produces more useful rankings than simpler approaches. To evaluate this, I looked at two things.

Label precision on targets with known CVEs. For OpenSSL 3.0.14 (3 known CVEs) and OpenSSH 9.8 (1 known CVE), I checked whether the known security fixes appeared in the top-ranked results:

| Target | Known CVE Functions | Appeared in Top 5 | Label Correct |
|--------|--------------------|--------------------|---------------|
| OpenSSL | Clear alignment for DSA-validation and session-duplication changes; weaker direct symbol-level alignment for `SSL_free_buffers` | Partial — top ranks plus unmatched B | 2/3 clearly aligned at symbol level; third reflected indirectly |
| OpenSSH | `_server_accept_loop` (rearchitected), `_grace_alarm_handler` (removed) | #1 matched, removal correctly reported | 1/1 + structural evidence |

In the runs I inspected manually, I didn't see obvious false positives in SEC-LIKELY for either target. SEC-POSSIBLE had a small number of non-CVE functions (stack hardening additions) that are arguably security-relevant even if they are not tied to a specific CVE.

Baseline comparison: triage ranking vs. "sort by size delta." A naive baseline for patch triage is to sort functions by absolute size change percentage and review the largest changes first. I compared this against the tool's ranking for the OpenSSL target:

- Size-delta baseline top 5: `_BN_generate_dsa_nonce` (-93.1%), `_EVP_PKEY_CTX_add1_hkdf_info` (+1712%), `_ossl_dsa_check_pairwise` (+81.8%), `_kdf_hkdf_derive` (+63.2%), `_dtls1_retransmit_buffered_messages` (+50.4%)
- PatchTriage top 5 (after matcher repair): `_EVP_PKEY_CTX_add1_hkdf_info` (SEC-LIKELY), `_ossl_dsa_check_pairwise` (SEC-POSSIBLE), `_EVP_Update_loop` (SEC-LIKELY), `_BN_generate_dsa_nonce` (BEHAVIOR), `_ossl_sm2_encrypt` (BEHAVIOR) — the HKDF helper now ranks #1 with stack protection and +1712% growth, while stack/bounds signals still lift `_EVP_Update_loop` without a huge size delta.

The size-delta baseline captures some of the same functions but misses `_EVP_Update_loop` entirely — it only grew 24.4% in size, but it added stack protection, which is a clear security signal. It does capture `_EVP_PKEY_CTX_add1_hkdf_info` (+1712%) but cannot explain why it matters (stack protection, not just growth). More importantly, the baseline provides no rationale: it says "this function changed a lot" but not why. On the zstd target with 1,132 matched functions, the size-delta baseline puts codec optimization functions in the top 10, while the triage heuristics correctly demote those and surface the 3 functions with actual stack hardening.

The part that ended up mattering most was the triage layer. Instead of leaving the analyst with a large flat diff, it attempts to prioritize the subset of changes that look most relevant to security review and to explain why they were prioritized.

### 5.10 Open-source synthetic test binaries

A pair of small server binaries with known planted security fixes. The tool identifies 7 of 10 matched functions as security-relevant, with the top-ranked functions showing unsafe API replacement (strcpy to strncpy, sprintf to snprintf), stack protection, and bounds checking additions.

Reproduction:
```bash
patchtriage run \
    corpus/open_source/server_v1 \
    corpus/open_source/server_v2 \
    -o corpus/open_source/results
```

## 6. Noise reduction: iterative improvements

During corpus testing, I ran into several sources of false positives that required targeted fixes:

| Issue | Root Cause | Fix |
|-------|-----------|-----|
| jq stdlib false positive | 5000-char embedded string containing "error" as language keyword | Filter strings >500 chars from error matching |
| zstd address constant noise | Pointer-like values (>4B) shifting between builds | Filter constants above 0x100000000 |
| zstd codec function noise | 139 codec functions with generic BEHAVIOR labels | Cap interestingness of codec-only functions without semantic evidence |
| OpenSSL data table phantom | `_ecp_nistz256_precomputed` (42KB data) misinterpreted as code | Detect internal-call-only churn with zero size change, cap to 0.5 |
| yq Go detection failure | Go markers at offset 6.4MB, past 2MB pre-scan | Added `__gopclntab` section check via otool |
| yq 23 "functions" | nm returns 0 symbols for Go binaries | Full Go pclntab parser for function names and sizes |
| OpenSSH false match security flags | Similarity-based matching force-paired removed/added functions with unrelated counterparts | Named functions absent from the other binary are sent directly to unmatched, bypassing the similarity pass |
| OpenSSL bipartite vs exact name | Hungarian matching optimized global sum while a same-named B row stayed unmatched | Post-pass repair reassigns to the unmatched same-named B symbol when unambiguous |

Each of these was found by running the tool on a real corpus target and inspecting the output for things that looked wrong. The fixes were validated against all other targets to make sure they didn't introduce regressions.

## 7. Development process

The project evolved a ton from the original proposal. The initial plan was a Ghidra-only tool that would extract features, match functions, and produce a report — with security triage as a stretch goal.

The first working version used Ghidra headless mode exclusively. It worked well on the synthetic test binaries (10 functions) and produced correct results on jq (1,449 functions, stripped). This validated the core approach of per-function feature extraction, similarity matching, and ranked reporting.

The "stretch goal" from the proposal (security triage heuristics) became the most important feature once I started testing on real targets. I built a rule-based triage engine that classifies each function diff with the five labels described in section 3.4. The key insight was that specific signal combinations (unsafe API removed + safer API added, stack protection added, bounds constants + new comparisons) are much stronger indicators than generic similarity deltas or size changes. The OpenSSL CVE validation confirmed this on a real target.

Running Ghidra on yq (a 10MB Go binary) is what pushed me toward adaptive backends. The Go runtime dominates the binary and Ghidra's analysis was slow and noisy. This led to the light backend for Go/Rust binaries, and eventually the native backend for symbolized C/C++ binaries. The native backend turned out to be the most useful day-to-day: it processes OpenSSL's 12,028 functions in about 2 seconds compared to several minutes under Ghidra.

The OpenSSH target exposed the most interesting matching failure mode. When sshd was split into sshd + sshd-session, 535 functions were removed from the binary. The similarity matcher force-paired them with unrelated new functions, producing false security flags. I spent a while trying threshold tuning (the bad pairs scored 0.70-0.79, while legitimate renamed pairs scored 0.74-0.90 — too much overlap), and eventually concluded that the fix had to be name-based rather than score-based. The three-pass matching pipeline came out of that.

Looking back, the most important change was abandoning the assumption that one analysis path would work across all targets. The project became much more reliable once I treated backend selection as part of the problem instead of as an implementation detail.

The final codebase is about 5,000 lines of Python across 15 modules, with 54 unit and integration tests that run in about a second. The test suite covers matching, triage, normalization, and report generation and runs on fixture data without requiring Ghidra or real binaries.

## 8. Applying the tool to new binary pairs

PatchTriage is designed to work on arbitrary binary pairs, not just the corpus targets above:

```bash
patchtriage run ./old_version ./new_version -o out
```

The tool will classify the binary, select an appropriate backend, extract features, match functions, and produce a ranked triage report. No configuration or Ghidra setup is needed for symbolized binaries.

### Where the current approach works best

- Symbolized C/C++ binaries (native backend): fast, accurate matching, reliable triage. This covers most open-source projects built from source and binaries that ship with symbols.
- Stripped C/C++ binaries (Ghidra backend): requires Ghidra but produces good results when Ghidra's analysis is stable. Function names will be anonymous, but the triage heuristics still work based on API calls, strings, and control-flow patterns.
- Go binaries (light backend with pclntab parsing): extracts real function names and sizes from Go's embedded metadata, even when standard tools report no symbols.
- Binaries with 100 to 12,000+ functions: the matching pipeline and triage heuristics have been tested across this range.

### Expected failure modes

- Stripped binaries without Ghidra: extraction falls back to the light backend, which gives coarser results (section-level rather than per-function).
- Cross-binary refactors: if a patch splits one binary into two (like the OpenSSH case), the tool compares a single pair and reports the missing functions as unmatched. The analyst would need to triage the new binary separately.
- Rust binaries: detection works, but per-function extraction depth on the light backend is limited.
- Heavily obfuscated or packed binaries: these will likely defeat both Ghidra and the native backend.

### Practical recommendations

Any project that ships release binaries or can be built from source across two versions makes a good candidate. Some examples: curl/libcurl (frequent security patches, symbolized builds), nginx (well-structured C, periodic security fixes), libpng/libjpeg-turbo (parser-heavy with known CVE history), sudo (small binary, high-impact security fixes). The fastest path is to build two versions from source with default flags.

## 9. Limitations

- When Ghidra recovers function boundaries but names remain anonymous, the triage can say "look here first" but cannot explain what the function does.
- The OpenSSH sshd-to-sshd-session split showed that the tool struggles when a patch reorganizes code across multiple binaries rather than within a single one.
- Extract-and-harden detection uses substring matching on function names, which misses cases where names diverge substantially (e.g., `BN_generate_dsa_nonce` to `ossl_bn_gen_dsa_nonce_fixed_top`).
- The light backend extracts names and sizes for Go binaries but not per-function call graphs or strings, so the triage signals available are limited.

## 10. Conclusion

The goal of this project was to help a reverse engineer / hacker decide what to reverse first after a patch lands. Across the seven corpus targets — spanning C, C++, and Go binaries from 10 to 12,000+ functions — the triage heuristics consistently separated security-relevant changes from noise.

For the two targets with well-documented CVEs (OpenSSL 3.0.14 and OpenSSH 9.8), the top-ranked functions align with the known security fixes:

- OpenSSL: all three advisories produced aligned ranked or unmatched results — CVE-2024-4603 and CVE-2024-2511 map clearly to ranked or unmatched symbols, while CVE-2024-4741 (`SSL_free_buffers`) is a smaller API-specific fix and appears more weakly at the symbol level. No obvious false positives in SEC-LIKELY on the evaluated run.
- OpenSSH: the CVE-2024-6387 fix components are ranked #1 (server_accept_loop rearchitecture), with corroborating evidence from 561 removed functions, 26 new functions, and signal handler shrinkage. Manual inspection found no incorrect matches among the 681 paired functions.

The baseline comparison in section 5.9 shows that the triage ranking outperforms naive size-delta sorting and, more importantly, provides rationale that the analyst can use to verify or override the tool's judgment. That rationale is what makes the output actionable rather than just another ranked list.

## Appendix: reproduction

See section 4 of this report and `README.md` in the repository for full installation, corpus setup, and CLI usage instructions.

## References

### Tools Mentioned

- BinDiff — Google/Zynamics. Binary diffing tool for function-level correspondence. https://github.com/google/bindiff
- Diaphora — Joxean Koret. Open-source binary diff tool (IDA Pro plugin). https://github.com/joxeankoret/diaphora
- DarunGrim — Jeong Wook Oh. Patch analysis framework. https://github.com/nicehash/DarunGrim
- TurboDiff — Nicolas Economou (Core Security). IDA Pro binary diffing plugin. https://www.coresecurity.com/core-labs/open-source-tools/turbodiff
- Ghidra — NSA. Software reverse engineering framework. https://ghidra-sre.org/

### Evaluation targets

- OpenSSL 3.0 series release notes (CVE-2024-4741, CVE-2024-4603, CVE-2024-2511). https://www.openssl.org/news/openssl-3.0-notes.html
- OpenSSH 9.8 release notes (CVE-2024-6387 "regreSSHion"). https://www.openssh.com/txt/release-9.8
- Qualys advisory for CVE-2024-6387. https://www.qualys.com/2024/07/01/cve-2024-6387/regresshion.txt
- SQLite release history. https://www.sqlite.org/changes.html
- Zstandard (zstd) releases. https://github.com/facebook/zstd/releases
- jq releases. https://github.com/jqlang/jq/releases
- yq releases. https://github.com/mikefarah/yq/releases

### Algorithms and methods

- Kuhn, H.W. "The Hungarian Method for the Assignment Problem." *Naval Research Logistics Quarterly*, 2(1-2):83–97, 1955. Implementation used: `scipy.optimize.linear_sum_assignment`. https://docs.scipy.org/doc/scipy/reference/generated/scipy.optimize.linear_sum_assignment.html
- Jaccard, P. "The Distribution of the Flora in the Alpine Zone." *New Phytologist*, 11(2):37–50, 1912. Used for set similarity across strings, calls, API families, and constants.
- Levenshtein, V.I. "Binary Codes Capable of Correcting Deletions, Insertions, and Reversals." *Soviet Physics Doklady*, 10(8):707–710, 1966. Used for function name similarity scoring.
- Cosine similarity. Used for mnemonic histogram and instruction group comparison. https://en.wikipedia.org/wiki/Cosine_similarity
