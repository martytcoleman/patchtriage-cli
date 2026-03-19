# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 14:06:14
**Binary A:** `/Users/marty/patchdiff-cli/targets/open_source/server_v1`
**Binary B:** `/Users/marty/patchdiff-cli/targets/open_source/server_v2`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 8 |
| Unmatched in A | 1 |
| Unmatched in B | 2 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-LIKELY]** | 3 |
| **[SEC-POSSIBLE]** | 3 |
| [REFACTOR] | 1 |
| [UNCHANGED] | 1 |

## Security Review Queue

1. `_parse_http_request` **[SEC-LIKELY]** (score 61.1)
2. `_parse_request_line` **[SEC-LIKELY]** (score 38.7)
3. `_url_decode` **[SEC-LIKELY]** (score 22.3)
4. `_parse_header_line` **[SEC-POSSIBLE]** (score 15.3)
5. `_format_log_entry` **[SEC-POSSIBLE]** (score 6.5)
6. `_print_request` **[SEC-POSSIBLE]** (score 6.5)

## Top 7 Changed Functions

### 1. `_parse_http_request` **[SEC-LIKELY]**

- **Interestingness:** 61.1
- **Match score:** 0.7067 (name_exact)
- **Triage confidence:** 1.0
- **Size:** 456 -> 788 (+72.8%)
- **Blocks:** 24 -> 37 (+13)
- **Instructions:** 114 -> 197 (+83)

**Heuristic Rationale:**
- Replaced unsafe `_strcpy` with `_strncpy`
- Added error/validation string(s): ['Rejecting request: bad Content-Length\n']
- Added checks and control-flow consistent with new input-validation or guard logic
- Control-flow and comparison growth suggests new guard or parser logic
- Added 13 blocks, 6 cmp(s), 20 branch(es) — possible new validation paths

  Ext calls added: `_fprintf`, `_fwrite`, `_strlen`, `_strncpy`
  Ext calls removed: `_atoi`, `_strcpy`
  Strings added: 'Body too large: %d bytes (max %d)\\n', 'Incomplete body: expected %d, got %zu\\n', 'Rejecting request: bad Content-Length\\n', 'Request too large: %zu bytes\\n' (+1 more)

---

### 2. `_parse_request_line` **[SEC-LIKELY]**

- **Interestingness:** 38.7
- **Match score:** 0.5568 (name_exact)
- **Triage confidence:** 1.0
- **Size:** 196 -> 340 (+73.5%)
- **Blocks:** 5 -> 12 (+7)
- **Instructions:** 49 -> 85 (+36)

**Heuristic Rationale:**
- Replaced unsafe `___strcpy_chk` with `_strncpy`
- Added error/validation string(s): ['Invalid path length: %zu\n']
- Added checks and control-flow consistent with new input-validation or guard logic
- Control-flow and comparison growth suggests new guard or parser logic
- Added 7 blocks, 2 cmp(s), 7 branch(es) — possible new validation paths

  Ext calls added: `_fprintf`, `_fwrite`, `_strncpy`, `_strstr`
  Ext calls removed: `___strcpy_chk`
  Strings added: '..', 'Invalid path length: %zu\\n', 'Path traversal detected\\n', 'Request path too long: %d bytes\\n'

---

### 3. `_url_decode` **[SEC-LIKELY]**

- **Interestingness:** 22.3
- **Match score:** 0.6428 (name_exact)
- **Triage confidence:** 0.97
- **Size:** 232 -> 372 (+60.3%)
- **Blocks:** 17 -> 23 (+6)
- **Instructions:** 58 -> 93 (+35)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)
- Added error/validation string(s): ['URL decode: output buffer too small\n']
- Added checks and control-flow consistent with new input-validation or guard logic
- Control-flow and comparison growth suggests new guard or parser logic
- Added 6 blocks, 3 cmp(s), 4 branch(es) — possible new validation paths

  Ext calls added: `___stack_chk_fail`, `_fwrite`
  Strings added: 'URL decode: output buffer too small\\n'

---

### 4. `_parse_header_line` **[SEC-POSSIBLE]**

- **Interestingness:** 15.3
- **Match score:** 0.8484 (name_exact)
- **Triage confidence:** 0.47
- **Size:** 124 -> 168 (+35.5%)
- **Blocks:** 6 -> 7 (+1)
- **Instructions:** 31 -> 42 (+11)

**Heuristic Rationale:**
- Replaced unsafe `_strcpy` with `_strncpy`
- Control-flow and comparison growth suggests new guard or parser logic

  Ext calls added: `_strlen`, `_strncpy`
  Ext calls removed: `_strcpy`

---

### 5. `_format_log_entry` **[SEC-POSSIBLE]**

- **Interestingness:** 6.5
- **Match score:** 0.82 (name_exact)
- **Triage confidence:** 0.38
- **Size:** 44 -> 44 (+0.0%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 11 -> 11 (+0)

**Heuristic Rationale:**
- Replaced unsafe `_sprintf` with `_snprintf`

  Ext calls added: `_snprintf`
  Ext calls removed: `_sprintf`

---

### 6. `_print_request` **[SEC-POSSIBLE]**

- **Interestingness:** 6.5
- **Match score:** 0.9064 (name_exact)
- **Triage confidence:** 0.38
- **Size:** 320 -> 316 (-1.2%)
- **Blocks:** 8 -> 8 (+0)
- **Instructions:** 80 -> 79 (-1)

**Heuristic Rationale:**
- Replaced unsafe `___sprintf_chk` with `_snprintf`

  Ext calls added: `_snprintf`
  Ext calls removed: `___sprintf_chk`

---

### 7. `entry` [REFACTOR]

- **Interestingness:** 21.2
- **Match score:** 0.8344 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 412 -> 216 (-47.6%)
- **Blocks:** 22 -> 8 (-14)
- **Instructions:** 103 -> 54 (-49)

**Heuristic Rationale:**
- Large size change (-47.6%) without clear security signals

  Ext calls removed: `_putchar`, `_strtol`
  Strings added: '=== mini_server v2.0 ==='
  Strings removed: '=== mini_server v1.0 ==='

---

## Unmatched Functions

### New in B (2)
- `_parse_content_length`
- `_validate_path`

### Removed from A (1)
- `_log_request`
