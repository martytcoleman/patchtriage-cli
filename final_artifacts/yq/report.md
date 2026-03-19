# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 14:06:38
**Binary A:** `/Users/marty/patchdiff-cli/tmp/yq-real-world/yq-v4.48.2-darwin-arm64`
**Binary B:** `/Users/marty/patchdiff-cli/tmp/yq-real-world/yq-v4.49.1-darwin-arm64`
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
| [BEHAVIOR] | 3 |
| [REFACTOR] | 1 |
| [UNCHANGED] | 19 |

## Security Review Queue

1. `section:__TEXT:__text` [BEHAVIOR] (score 2.0)
2. `section:__DATA_CONST:__gopclntab` [BEHAVIOR] (score 2.0)
3. `__binary__` [BEHAVIOR] (score 2.0)

## Top 4 Changed Functions

### 1. `section:__TEXT:__text` [BEHAVIOR]

- **Interestingness:** 2.0
- **Match score:** 0.85 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 4508292 -> 4509972 (+0.0%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 12000 -> 12000 (+0)

**Heuristic Rationale:**
- Coarse binary-region change surfaced by fallback analysis


---

### 2. `section:__DATA_CONST:__gopclntab` [BEHAVIOR]

- **Interestingness:** 2.0
- **Match score:** 0.77 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 3114304 -> 3114944 (+0.0%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 0 -> 0 (+0)

**Heuristic Rationale:**
- Coarse binary-region change surfaced by fallback analysis


---

### 3. `__binary__` [BEHAVIOR]

- **Interestingness:** 2.0
- **Match score:** 0.8492 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 10997522 -> 10997522 (+0.0%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 12000 -> 12000 (+0)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Strings added: 'Go build ID: "q2hY0YtN-3sB8ybJE-Jt/lTAkhEBRMc6ciKECGT99/v4LxqxBLF5Kp8ufaXZSy/i1U1wlGtqa...'
  Strings removed: 'Go build ID: "7NfQnVov7nuquJ1DYlcE/mmjmINSqlEl56kMYIaaJ/v4LxqxBLF5Kp8ufaXZSy/PIt4LaME_5...'

---

### 4. `section:__TEXT:__rodata` [REFACTOR]

- **Interestingness:** 2.0
- **Match score:** 0.85 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 928857 -> 929369 (+0.1%)
- **Blocks:** 1 -> 1 (+0)
- **Instructions:** 12000 -> 12000 (+0)

**Heuristic Rationale:**
- Coarse binary-region size change without direct security evidence


---
