# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 15:09:41
**Binary A:** `/Users/marty/patchdiff-cli/corpus/yq/yq-v4.48.2-darwin-arm64`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/yq/yq-v4.49.1-darwin-arm64`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 23 |
| Unmatched in A | 0 |
| Unmatched in B | 0 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| [BEHAVIOR] | 1 |
| [UNCHANGED] | 22 |

## Security Review Queue

1. `__binary__` [BEHAVIOR] (score 2.0)

## Collapsed Families

- `section:__TEXT:__rodata` represents 3 similar `unchanged` changes

## Top 2 Changed Functions

### 1. `__binary__` [BEHAVIOR]

- **Interestingness:** 2.0
- **Match score:** 1.0492 (name_exact)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, formatter, io, memory_heavy
- **Size:** 10997522 -> 10997522 (+0.0%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 12000 -> 12000 (+0)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: 'Go build ID: "q2hY0YtN-3sB8ybJE-Jt/lTAkhEBRMc6ciKECGT99/v4LxqxBLF5Kp8ufaXZSy/i1U1wlGtqa...'
  Strings removed: 'Go build ID: "7NfQnVov7nuquJ1DYlcE/mmjmINSqlEl56kMYIaaJ/v4LxqxBLF5Kp8ufaXZSy/PIt4LaME_5...'

---

### 2. `section:__TEXT:__rodata` [UNCHANGED]

**Collapsed similar changes:** 2
**Examples:** `section:__TEXT:__text`, `section:__DATA_CONST:__gopclntab`

- **Interestingness:** 1.6
- **Match score:** 1.05 (name_exact)
- **Triage confidence:** 0.0
- **Size:** 928857 -> 929369 (+0.1%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 12000 -> 12000 (+0)

**Heuristic Rationale:**
- Primarily structural churn without semantic evidence


---
