# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 15:09:45
**Binary A:** `/Users/marty/patchdiff-cli/corpus/zstd/zstd-1.5.5/programs/zstd`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/zstd/zstd-1.5.7/programs/zstd`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 1134 |
| Unmatched in A | 0 |
| Unmatched in B | 27 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-POSSIBLE]** | 2 |
| [BEHAVIOR] | 139 |
| [REFACTOR] | 17 |
| [UNCHANGED] | 976 |

## Security Review Queue

1. `_ZSTD_compressBlock_doubleFast` **[SEC-POSSIBLE]** (score 137.7)
2. `_ZSTD_compressSeqStore_singleBlock` **[SEC-POSSIBLE]** (score 21.6)
3. `_main` [BEHAVIOR] (score 150.3)
4. `_ZSTD_compressBlock_fast` [BEHAVIOR] (score 143.6)
5. `_ZSTD_compressBlock_fast_dictMatchState` [BEHAVIOR] (score 124.3)
6. `_ZSTD_compressBlock_doubleFast_dictMatchState` [BEHAVIOR] (score 116.4)
7. `_HUF_decompress4X2_usingDTable_internal` [BEHAVIOR] (score 93.4)
8. `_ZSTD_decompressSequencesLong` [BEHAVIOR] (score 73.0)
9. `_ZSTD_compressBlock_opt2` [BEHAVIOR] (score 66.9)
10. `_ZDICT_trainFromBuffer_legacy` [BEHAVIOR] (score 51.0)

## Top 30 Changed Functions

### 1. `_ZSTD_compressBlock_doubleFast` **[SEC-POSSIBLE]**

- **Interestingness:** 137.7
- **Match score:** 0.8229 (name_exact)
- **Triage confidence:** 0.31
- **Inferred roles:** codec
- **Size:** 11536 -> 11716 (+1.6%)
- **Blocks:** 521 -> 491 (-30)
- **Instructions:** 2884 -> 2929 (+45)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)

  Ext calls added: `___stack_chk_fail`

---

### 2. `_ZSTD_compressSeqStore_singleBlock` **[SEC-POSSIBLE]**

- **Interestingness:** 21.6
- **Match score:** 0.9297 (name_exact)
- **Triage confidence:** 0.34
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 764 -> 820 (+7.3%)
- **Blocks:** 29 -> 31 (+2)
- **Instructions:** 191 -> 205 (+14)

**Heuristic Rationale:**
- Added bounds constant(s) ['0x80'] with 5 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic

  Ext calls removed: `___stack_chk_fail`

---

### 3. `_main` [BEHAVIOR]

- **Interestingness:** 150.3
- **Match score:** 1.0378 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** dispatcher, formatter, io
- **Size:** 12440 -> 12824 (+3.1%)
- **Blocks:** 578 -> 592 (+14)
- **Instructions:** 3110 -> 3206 (+96)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 4. `_ZSTD_compressBlock_fast` [BEHAVIOR]

- **Interestingness:** 143.6
- **Match score:** 1.0401 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 14268 -> 14328 (+0.4%)
- **Blocks:** 567 -> 562 (-5)
- **Instructions:** 3567 -> 3582 (+15)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 5. `_ZSTD_compressBlock_fast_dictMatchState` [BEHAVIOR]

- **Interestingness:** 124.3
- **Match score:** 1.0375 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 9912 -> 10252 (+3.4%)
- **Blocks:** 377 -> 393 (+16)
- **Instructions:** 2478 -> 2563 (+85)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 6. `_ZSTD_compressBlock_doubleFast_dictMatchState` [BEHAVIOR]

- **Interestingness:** 116.4
- **Match score:** 1.0393 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 13360 -> 13012 (-2.6%)
- **Blocks:** 521 -> 529 (+8)
- **Instructions:** 3340 -> 3253 (-87)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 7. `_HUF_decompress4X2_usingDTable_internal` [BEHAVIOR]

- **Interestingness:** 93.4
- **Match score:** 1.0347 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 6696 -> 7044 (+5.2%)
- **Blocks:** 176 -> 201 (+25)
- **Instructions:** 1674 -> 1761 (+87)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 8. `_ZSTD_decompressSequencesLong` [BEHAVIOR]

- **Interestingness:** 73.0
- **Match score:** 1.0357 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 6296 -> 6436 (+2.2%)
- **Blocks:** 236 -> 243 (+7)
- **Instructions:** 1574 -> 1609 (+35)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 9. `_ZSTD_compressBlock_opt2` [BEHAVIOR]

- **Interestingness:** 66.9
- **Match score:** 1.0336 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3660 -> 4340 (+18.6%)
- **Blocks:** 97 -> 108 (+11)
- **Instructions:** 915 -> 1085 (+170)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 10. `_ZDICT_trainFromBuffer_legacy` [BEHAVIOR]

- **Interestingness:** 51.0
- **Match score:** 1.0498 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, formatter, io, memory_heavy
- **Size:** 5368 -> 5376 (+0.1%)
- **Blocks:** 227 -> 227 (+0)
- **Instructions:** 1342 -> 1344 (+2)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 11. `_ZSTD_compressContinue_internal` [BEHAVIOR]

- **Interestingness:** 45.8
- **Match score:** 1.0294 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 2144 -> 2360 (+10.1%)
- **Blocks:** 66 -> 72 (+6)
- **Instructions:** 536 -> 590 (+54)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 12. `_ZSTD_compressSuperBlock` [BEHAVIOR]

- **Interestingness:** 43.2
- **Match score:** 1.0039 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 3120 -> 2844 (-8.8%)
- **Blocks:** 104 -> 93 (-11)
- **Instructions:** 780 -> 711 (-69)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 13. `_ZSTD_decompressSequencesSplitLitBuffer` [BEHAVIOR]

- **Interestingness:** 41.7
- **Match score:** 1.0307 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 4228 -> 3888 (-8.0%)
- **Blocks:** 152 -> 150 (-2)
- **Instructions:** 1057 -> 972 (-85)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 14. `_ZSTDMT_initCStream_internal` [BEHAVIOR]

- **Interestingness:** 41.6
- **Match score:** 1.035 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, io, memory_heavy
- **Size:** 2352 -> 2516 (+7.0%)
- **Blocks:** 90 -> 96 (+6)
- **Instructions:** 588 -> 629 (+41)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 15. `_ZSTD_resetCCtx_internal` [BEHAVIOR]

- **Interestingness:** 41.4
- **Match score:** 1.0443 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 3096 -> 3012 (-2.7%)
- **Blocks:** 87 -> 86 (-1)
- **Instructions:** 774 -> 753 (-21)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 16. `_ZSTD_compressBlock_lazy2_dictMatchState_row` [BEHAVIOR]

- **Interestingness:** 40.4
- **Match score:** 1.047 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 4508 -> 4488 (-0.4%)
- **Blocks:** 207 -> 206 (-1)
- **Instructions:** 1127 -> 1122 (-5)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 17. `_FIO_decompressSrcFile` [BEHAVIOR]

- **Interestingness:** 39.9
- **Match score:** 1.0349 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec, formatter, io
- **Size:** 3452 -> 3196 (-7.4%)
- **Blocks:** 165 -> 154 (-11)
- **Instructions:** 863 -> 799 (-64)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 18. `_ZSTD_compressBlock_lazy2_dedicatedDictSearch_row` [BEHAVIOR]

- **Interestingness:** 39.8
- **Match score:** 1.047 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 4508 -> 4488 (-0.4%)
- **Blocks:** 207 -> 206 (-1)
- **Instructions:** 1127 -> 1122 (-5)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 19. `_ZSTD_compressBlock_lazy2_row` [BEHAVIOR]

- **Interestingness:** 39.5
- **Match score:** 1.0448 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 4116 -> 3940 (-4.3%)
- **Blocks:** 189 -> 189 (+0)
- **Instructions:** 1029 -> 985 (-44)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 20. `_FIO_createCResources` [BEHAVIOR]

- **Interestingness:** 38.0
- **Match score:** 1.0493 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, io
- **Size:** 5268 -> 5296 (+0.5%)
- **Blocks:** 288 -> 290 (+2)
- **Instructions:** 1317 -> 1324 (+7)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 21. `_ZSTD_compressBlock_lazy2_extDict_row` [BEHAVIOR]

- **Interestingness:** 36.9
- **Match score:** 1.0347 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 4144 -> 4484 (+8.2%)
- **Blocks:** 190 -> 188 (-2)
- **Instructions:** 1036 -> 1121 (+85)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 22. `_HUF_decompress4X1_usingDTable_internal` [BEHAVIOR]

- **Interestingness:** 36.1
- **Match score:** 1.0377 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 4368 -> 4464 (+2.2%)
- **Blocks:** 118 -> 121 (+3)
- **Instructions:** 1092 -> 1116 (+24)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 23. `_ZSTD_decompressMultiFrame` [BEHAVIOR]

- **Interestingness:** 35.5
- **Match score:** 1.0369 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 1904 -> 2028 (+6.5%)
- **Blocks:** 68 -> 72 (+4)
- **Instructions:** 476 -> 507 (+31)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 24. `_ZSTD_compressBlock_lazy_dictMatchState_row` [BEHAVIOR]

- **Interestingness:** 35.0
- **Match score:** 1.0483 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3884 -> 3872 (-0.3%)
- **Blocks:** 173 -> 172 (-1)
- **Instructions:** 971 -> 968 (-3)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 25. `_ZSTD_compressBlock_lazy_dedicatedDictSearch_row` [BEHAVIOR]

- **Interestingness:** 35.0
- **Match score:** 1.0483 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3884 -> 3872 (-0.3%)
- **Blocks:** 173 -> 172 (-1)
- **Instructions:** 971 -> 968 (-3)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 26. `_ZSTD_compressBlock_lazy_extDict_row` [BEHAVIOR]

- **Interestingness:** 34.6
- **Match score:** 1.0364 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3736 -> 3584 (-4.1%)
- **Blocks:** 152 -> 148 (-4)
- **Instructions:** 934 -> 896 (-38)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 27. `_ZSTD_decompressStream` [BEHAVIOR]

- **Interestingness:** 33.4
- **Match score:** 1.0468 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 2844 -> 2912 (+2.4%)
- **Blocks:** 117 -> 117 (+0)
- **Instructions:** 711 -> 728 (+17)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 28. `_ZSTD_compressBlock_lazy_row` [BEHAVIOR]

- **Interestingness:** 32.8
- **Match score:** 1.046 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3520 -> 3460 (-1.7%)
- **Blocks:** 149 -> 149 (+0)
- **Instructions:** 880 -> 865 (-15)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 29. `_BMK_benchCLevel` [REFACTOR]
  Matched to: `_BMK_benchCLevels`

- **Interestingness:** 32.5
- **Match score:** 0.8506 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** benchmark, formatter, io
- **Size:** 332 -> 472 (+42.2%)
- **Blocks:** 12 -> 22 (+10)
- **Instructions:** 83 -> 118 (+35)

**Heuristic Rationale:**
- Large size change (42.2%) without clear security signals


---

### 30. `_ZSTD_compressBlock_opt0` [BEHAVIOR]

- **Interestingness:** 32.3
- **Match score:** 1.0348 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 3604 -> 3564 (-1.1%)
- **Blocks:** 102 -> 97 (-5)
- **Instructions:** 901 -> 891 (-10)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

## Unmatched Functions

### New in B (27)
- `_HIST_add`
- `_HUF_readCTableHeader`
- `_ZSTD_convertBlockSequences`
- `_ZSTD_get1BlockSummary`
- `_ZSTD_compressSequencesAndLiterals`
- `_ZSTD_compressSequencesAndLiterals_internal`
- `_ZSTD_CCtxParams_registerSequenceProducer`
- `_ZSTD_compressSubBlock`
- `_ZSTD_splitBlock`
- `_ZSTD_recordFingerprint_43`
- `_ZSTD_recordFingerprint_11`
- `_ZSTD_recordFingerprint_5`
- `_ZSTD_recordFingerprint_1`
- `_ZSTDMT_freeBufferPool`
- `_ZSTDMT_freeCCtxPool`
- `_ZSTD_decodeLiteralsBlock_wrapper`
- `_formatString_u`
- `_LOREM_genBlock`
- `_LOREM_genBuffer`
- `_generateWord`
- `_formatString_u.cold.1`
- `_formatString_u.cold.2`
- `_FIO_decompressSrcFile.cold.5`
- `_LOREM_genBlock.cold.1`
- `_LOREM_genBlock.cold.2`
- `_LOREM_genBlock.cold.3`
- `_generateWord.cold.1`
