# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 15:09:38
**Binary A:** `/Users/marty/patchdiff-cli/corpus/open_source/server_v1`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/open_source/server_v2`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 10 |
| Unmatched in A | 0 |
| Unmatched in B | 1 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-LIKELY]** | 4 |
| **[SEC-POSSIBLE]** | 3 |
| [REFACTOR] | 2 |
| [UNCHANGED] | 1 |

## Security Review Queue

1. `_parse_http_request` **[SEC-LIKELY]** (score 65.8)
2. `_parse_content_length` **[SEC-LIKELY]** (score 41.6)
3. `_parse_request_line` **[SEC-LIKELY]** (score 35.7)
4. `_url_decode` **[SEC-LIKELY]** (score 27.6)
5. `_parse_header_line` **[SEC-POSSIBLE]** (score 18.8)
6. `_print_request` **[SEC-POSSIBLE]** (score 8.9)
7. `_format_log_entry` **[SEC-POSSIBLE]** (score 6.8)

## Top 10 Changed Functions

### 1. `_parse_http_request` **[SEC-LIKELY]**

- **Interestingness:** 65.8
- **Match score:** 0.8796 (name_exact)
- **Triage confidence:** 0.66
- **Inferred roles:** allocator, control_heavy, formatter, io, memory_heavy, parser
- **Size:** 396 -> 684 (+72.7%)
- **Blocks:** 22 -> 39 (+17)
- **Instructions:** 99 -> 171 (+72)

**Heuristic Rationale:**
- Replaced unsafe `_strcpy` with `_strncpy`
- Control-flow and comparison growth suggests new guard or parser logic
- Added 17 blocks, 6 cmp(s), 16 branch(es) — possible new validation paths

  Ext calls added: `_fprintf`, `_fwrite`, `_strlen`, `_strncpy`
  Ext calls removed: `_atoi`, `_strcpy`
  API families added: ['file']

---

### 2. `_parse_content_length` **[SEC-LIKELY]**

- **Interestingness:** 41.6
- **Match score:** 0.3847 (name_exact)
- **Triage confidence:** 0.84
- **Inferred roles:** control_heavy, formatter, io, parser
- **Size:** 4 -> 188 (+4600.0%)
- **Blocks:** 1 -> 10 (+9)
- **Instructions:** 0 -> 47 (+47)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)
- Added bounds constant(s) ['0x10', '0x20', '0x40', '0x100'] with 3 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic
- Added 9 blocks, 3 cmp(s), 9 branch(es) — possible new validation paths

  Ext calls added: `___error`, `___stack_chk_fail`, `_fprintf`, `_strtol`
  API families added: ['file', 'string']

---

### 3. `_parse_request_line` **[SEC-LIKELY]**

- **Interestingness:** 35.7
- **Match score:** 0.7802 (name_exact)
- **Triage confidence:** 0.66
- **Inferred roles:** control_heavy, formatter, io, parser
- **Size:** 172 -> 288 (+67.4%)
- **Blocks:** 7 -> 12 (+5)
- **Instructions:** 43 -> 72 (+29)

**Heuristic Rationale:**
- Replaced unsafe `___strcpy_chk` with `_strncpy`
- Control-flow and comparison growth suggests new guard or parser logic
- Added 5 blocks, 2 cmp(s), 5 branch(es) — possible new validation paths

  Ext calls added: `_fprintf`, `_fwrite`, `_strncpy`, `_strstr`
  Ext calls removed: `___strcpy_chk`
  API families added: ['file']

---

### 4. `_url_decode` **[SEC-LIKELY]**

- **Interestingness:** 27.6
- **Match score:** 0.8089 (name_exact)
- **Triage confidence:** 0.59
- **Inferred roles:** codec, control_heavy, io, parser
- **Size:** 180 -> 308 (+71.1%)
- **Blocks:** 6 -> 11 (+5)
- **Instructions:** 45 -> 77 (+32)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)
- Control-flow and comparison growth suggests new guard or parser logic
- Added 5 blocks, 3 cmp(s), 4 branch(es) — possible new validation paths

  Ext calls added: `___stack_chk_fail`, `_fwrite`
  API families added: ['file']

---

### 5. `_parse_header_line` **[SEC-POSSIBLE]**

- **Interestingness:** 18.8
- **Match score:** 0.8657 (name_exact)
- **Triage confidence:** 0.47
- **Inferred roles:** control_heavy, parser
- **Size:** 112 -> 156 (+39.3%)
- **Blocks:** 6 -> 8 (+2)
- **Instructions:** 28 -> 39 (+11)

**Heuristic Rationale:**
- Replaced unsafe `_strcpy` with `_strncpy`
- Control-flow and comparison growth suggests new guard or parser logic

  Ext calls added: `_strlen`, `_strncpy`
  Ext calls removed: `_strcpy`

---

### 6. `_print_request` **[SEC-POSSIBLE]**

- **Interestingness:** 8.9
- **Match score:** 0.953 (name_exact)
- **Triage confidence:** 0.38
- **Inferred roles:** formatter
- **Size:** 252 -> 248 (-1.6%)
- **Blocks:** 14 -> 14 (+0)
- **Instructions:** 63 -> 62 (-1)

**Heuristic Rationale:**
- Replaced unsafe `___sprintf_chk` with `_snprintf`

  Ext calls added: `_snprintf`
  Ext calls removed: `___sprintf_chk`

---

### 7. `_format_log_entry` **[SEC-POSSIBLE]**

- **Interestingness:** 6.8
- **Match score:** 0.87 (name_exact)
- **Triage confidence:** 0.38
- **Inferred roles:** formatter, logger
- **Size:** 32 -> 32 (+0.0%)
- **Blocks:** 3 -> 3 (+0)
- **Instructions:** 8 -> 8 (+0)

**Heuristic Rationale:**
- Replaced unsafe `_sprintf` with `_snprintf`

  Ext calls added: `_snprintf`
  Ext calls removed: `_sprintf`

---

### 8. `_main` [REFACTOR]

- **Interestingness:** 13.2
- **Match score:** 0.8904 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, dispatcher, formatter, memory_heavy
- **Size:** 320 -> 168 (-47.5%)
- **Blocks:** 18 -> 14 (-4)
- **Instructions:** 80 -> 42 (-38)

**Heuristic Rationale:**
- Large size change (-47.5%) without clear security signals

  Ext calls removed: `_putchar`, `_strtol`

---

### 9. `_log_request` [REFACTOR]

- **Interestingness:** 3.3
- **Match score:** 0.4642 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** formatter, logger
- **Size:** 20 -> 4 (-80.0%)
- **Blocks:** 2 -> 1 (-1)
- **Instructions:** 5 -> 0 (-5)

**Heuristic Rationale:**
- Large size change (-80.0%) without clear security signals

  Ext calls removed: `_printf`

---

### 10. `_free_request` [UNCHANGED]

- **Interestingness:** 0.6
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 44 -> 44 (+0.0%)
- **Blocks:** 3 -> 3 (+0)
- **Instructions:** 11 -> 11 (+0)


---

## Unmatched Functions

### New in B (1)
- `_validate_path`
