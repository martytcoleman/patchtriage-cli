# PatchTriage Security Patch Triage Report

**Generated:** 2026-03-19 23:35:07
**Binary A:** `/Users/marty/patchdiff-cli/corpus/openssl/openssl-3.0.13-darwin-arm64`
**Binary B:** `/Users/marty/patchdiff-cli/corpus/openssl/openssl-3.0.14-darwin-arm64`
**Primary question:** Which changed functions deserve immediate reverse-engineering attention?

## Summary

| Metric | Value |
|--------|-------|
| Matched functions | 12028 |
| Unmatched in A | 0 |
| Unmatched in B | 12 |

### Triage Breakdown

| Label | Count |
|-------|-------|
| **[SEC-LIKELY]** | 1 |
| **[SEC-POSSIBLE]** | 1 |
| [BEHAVIOR] | 24 |
| [REFACTOR] | 33 |
| [UNCHANGED] | 11969 |

## Security Review Queue

1. `_ossl_dsa_check_pairwise` **[SEC-POSSIBLE]** (score 19.4)
2. `_EVP_Update_loop` **[SEC-LIKELY]** (score 15.6)
3. `_ossl_sm2_encrypt` [BEHAVIOR] (score 28.0)
4. `_ossl_sm2_decrypt` [BEHAVIOR] (score 25.1)
5. `_ssl_session_dup` [BEHAVIOR] (score 19.2)
6. `_ossl_sm2_compute_z_digest` [BEHAVIOR] (score 8.8)
7. `_poll_for_response` [BEHAVIOR] (score 8.5)
8. `_cmp_server` [BEHAVIOR] (score 8.0)
9. `_spawn_loop` [BEHAVIOR] (score 7.1)
10. `_EVP_PKEY_verify_recover` [BEHAVIOR] (score 6.5)

## Collapsed Families

- `_SSL_free_buffers` represents 5 similar `refactor` changes
- `_evp_keymgmt_util_export_to_provider` represents 6 similar `unchanged` changes

## Top 30 Changed Functions

### 1. `_ossl_dsa_check_pairwise` **[SEC-POSSIBLE]**

- **Interestingness:** 19.4
- **Match score:** 0.8158 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.28
- **Inferred roles:** control_heavy, validator
- **Size:** 176 -> 320 (+81.8%)
- **Blocks:** 9 -> 18 (+9)
- **Instructions:** 44 -> 80 (+36)

**Heuristic Rationale:**
- Control-flow and comparison growth suggests new guard or parser logic
- Added 9 blocks, 2 cmp(s), 9 branch(es) — possible new validation paths


---

### 2. `_EVP_Update_loop` **[SEC-LIKELY]**

- **Interestingness:** 15.6
- **Match score:** 0.6523 (name_repair_unmatched_b)
- **Triage confidence:** 0.84
- **Size:** 360 -> 448 (+24.4%)
- **Blocks:** 13 -> 18 (+5)
- **Instructions:** 90 -> 112 (+22)

**Heuristic Rationale:**
- Added stack protection (`stack_chk_fail`)
- Added bounds constant(s) ['0x80'] with 1 new comparison(s)
- Control-flow and comparison growth suggests new guard or parser logic
- Added 5 blocks, 1 cmp(s), 6 branch(es) — possible new validation paths

  Ext calls added: `___stack_chk_fail`

---

### 3. `_ossl_sm2_encrypt` [BEHAVIOR]

- **Interestingness:** 28.0
- **Match score:** 0.8559 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 1944 -> 2256 (+16.0%)
- **Blocks:** 100 -> 110 (+10)
- **Instructions:** 486 -> 564 (+78)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 4. `_ENGINE_load_private_key` [REFACTOR]
  Matched to: `_ENGINE_load_public_key`

- **Interestingness:** 26.7
- **Match score:** 0.8133 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Inferred roles:** control_heavy, parser
- **Size:** 552 -> 216 (-60.9%)
- **Blocks:** 38 -> 9 (-29)
- **Instructions:** 138 -> 54 (-84)

**Heuristic Rationale:**
- Large size change (-60.9%) without clear security signals


---

### 5. `_ossl_sm2_decrypt` [BEHAVIOR]

- **Interestingness:** 25.1
- **Match score:** 0.8772 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 1452 -> 1692 (+16.5%)
- **Blocks:** 55 -> 64 (+9)
- **Instructions:** 363 -> 423 (+60)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 6. `_BN_generate_dsa_nonce` [REFACTOR]
  Matched to: `_ossl_bn_gen_dsa_nonce_fixed_top`

- **Interestingness:** 24.7
- **Match score:** 0.8647 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 640 -> 796 (+24.4%)
- **Blocks:** 34 -> 47 (+13)
- **Instructions:** 160 -> 199 (+39)

**Heuristic Rationale:**
- Large size change (24.4%) without clear security signals


---

### 7. `_ssl_session_dup` [BEHAVIOR]

- **Interestingness:** 19.2
- **Match score:** 0.435 (name_repair_unmatched_b)
- **Triage confidence:** 0.25
- **Inferred roles:** allocator, memory_heavy
- **Size:** 496 -> 28 (-94.4%)
- **Blocks:** 21 -> 3 (-18)
- **Instructions:** 124 -> 7 (-117)

**Heuristic Rationale:**
- Removed call to unsafe `_memcpy`
- Function shrunk significantly and related function(s) added in B: _ssl_session_dup_intern — possible extract-and-harden refactor

  Ext calls removed: `_memcpy`

---

### 8. `_ossl_provider_new` [REFACTOR]

- **Interestingness:** 17.9
- **Match score:** 0.8622 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, memory_heavy
- **Size:** 308 -> 492 (+59.7%)
- **Blocks:** 15 -> 24 (+9)
- **Instructions:** 77 -> 123 (+46)

**Heuristic Rationale:**
- Large size change (59.7%) without clear security signals


---

### 9. `_BIO_do_connect_retry` [REFACTOR]

- **Interestingness:** 15.8
- **Match score:** 0.7545 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 776 -> 604 (-22.2%)
- **Blocks:** 53 -> 40 (-13)
- **Instructions:** 194 -> 151 (-43)

**Heuristic Rationale:**
- Large size change (-22.2%) without clear security signals

  Ext calls removed: `_usleep`

---

### 10. `_BIO_wait` [REFACTOR]

- **Interestingness:** 12.9
- **Match score:** 0.619 (name_repair_unmatched_b)
- **Triage confidence:** 0.0
- **Size:** 256 -> 100 (-60.9%)
- **Blocks:** 15 -> 8 (-7)
- **Instructions:** 64 -> 25 (-39)

**Heuristic Rationale:**
- Large size change (-60.9%) without clear security signals

  Ext calls removed: `_time`, `_usleep`

---

### 11. `_BN_ucmp` [REFACTOR]

- **Interestingness:** 9.8
- **Match score:** 0.8047 (name_repair_unmatched_b)
- **Triage confidence:** 0.0
- **Size:** 88 -> 200 (+127.3%)
- **Blocks:** 7 -> 10 (+3)
- **Instructions:** 22 -> 50 (+28)

**Heuristic Rationale:**
- Large size change (127.3%) without clear security signals


---

### 12. `_EVP_PKEY_CTX_set1_scrypt_salt` [REFACTOR]
  Matched to: `_kdf_hkdf_settable_ctx_params`

- **Interestingness:** 9.4
- **Match score:** 0.7419 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 32 -> 76 (+137.5%)
- **Blocks:** 1 -> 7 (+6)
- **Instructions:** 8 -> 19 (+11)

**Heuristic Rationale:**
- Large size change (137.5%) without clear security signals


---

### 13. `_SSL_CIPHER_get_version` [REFACTOR]
  Matched to: `_RECORD_LAYER_data_present`

- **Interestingness:** 8.9
- **Match score:** 0.7461 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 32 -> 76 (+137.5%)
- **Blocks:** 4 -> 6 (+2)
- **Instructions:** 8 -> 19 (+11)

**Heuristic Rationale:**
- Large size change (137.5%) without clear security signals


---

### 14. `_kdf_scrypt_gettable_ctx_params` [REFACTOR]

- **Interestingness:** 8.9
- **Match score:** 0.6569 (name_repair_unmatched_b)
- **Triage confidence:** 0.0
- **Size:** 8 -> 76 (+850.0%)
- **Blocks:** 2 -> 7 (+5)
- **Instructions:** 2 -> 19 (+17)

**Heuristic Rationale:**
- Large size change (850.0%) without clear security signals


---

### 15. `_kdf_tls1_prf_gettable_ctx_params` [REFACTOR]

- **Interestingness:** 8.9
- **Match score:** 0.6569 (name_repair_unmatched_b)
- **Triage confidence:** 0.0
- **Size:** 8 -> 76 (+850.0%)
- **Blocks:** 2 -> 7 (+5)
- **Instructions:** 2 -> 19 (+17)

**Heuristic Rationale:**
- Large size change (850.0%) without clear security signals


---

### 16. `_ossl_sm2_compute_z_digest` [BEHAVIOR]

- **Interestingness:** 8.8
- **Match score:** 0.892 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 1020 -> 1076 (+5.5%)
- **Blocks:** 58 -> 61 (+3)
- **Instructions:** 255 -> 269 (+14)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 17. `_OSSL_ENCODER_to_bio` [REFACTOR]

- **Interestingness:** 8.7
- **Match score:** 0.856 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Inferred roles:** codec
- **Size:** 124 -> 212 (+71.0%)
- **Blocks:** 8 -> 12 (+4)
- **Instructions:** 31 -> 53 (+22)

**Heuristic Rationale:**
- Large size change (71.0%) without clear security signals


---

### 18. `_poll_for_response` [BEHAVIOR]

- **Interestingness:** 8.5
- **Match score:** 0.8381 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 872 -> 916 (+5.0%)
- **Blocks:** 42 -> 43 (+1)
- **Instructions:** 218 -> 229 (+11)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_sleep`

---

### 19. `_ossl_sleep` [REFACTOR]

- **Interestingness:** 8.2
- **Match score:** 0.4886 (name_repair_unmatched_b)
- **Triage confidence:** 0.0
- **Size:** 8 -> 68 (+750.0%)
- **Blocks:** 1 -> 2 (+1)
- **Instructions:** 2 -> 17 (+15)

**Heuristic Rationale:**
- Large size change (750.0%) without clear security signals

  Ext calls added: `_sleep`

---

### 20. `_cmp_server` [BEHAVIOR]

- **Interestingness:** 8.0
- **Match score:** 0.8104 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 540 -> 548 (+1.5%)
- **Blocks:** 28 -> 30 (+2)
- **Instructions:** 135 -> 137 (+2)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_sleep`

---

### 21. `_EVP_PKEY_verify` [REFACTOR]

- **Interestingness:** 7.8
- **Match score:** 0.8795 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Inferred roles:** validator
- **Size:** 188 -> 244 (+29.8%)
- **Blocks:** 13 -> 17 (+4)
- **Instructions:** 47 -> 61 (+14)

**Heuristic Rationale:**
- Large size change (29.8%) without clear security signals


---

### 22. `_OSSL_ENCODER_to_data` [REFACTOR]

- **Interestingness:** 7.5
- **Match score:** 0.8677 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Inferred roles:** allocator, codec, memory_heavy
- **Size:** 400 -> 292 (-27.0%)
- **Blocks:** 19 -> 14 (-5)
- **Instructions:** 100 -> 73 (-27)

**Heuristic Rationale:**
- Large size change (-27.0%) without clear security signals


---

### 23. `_spawn_loop` [BEHAVIOR]

- **Interestingness:** 7.1
- **Match score:** 0.8752 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** io
- **Size:** 988 -> 996 (+0.8%)
- **Blocks:** 66 -> 68 (+2)
- **Instructions:** 247 -> 249 (+2)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_sleep`

---

### 24. `_evp_keymgmt_util_find_operation_cache` [REFACTOR]

- **Interestingness:** 6.8
- **Match score:** 0.8836 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 140 -> 172 (+22.9%)
- **Blocks:** 10 -> 12 (+2)
- **Instructions:** 35 -> 43 (+8)

**Heuristic Rationale:**
- Large size change (22.9%) without clear security signals


---

### 25. `_EVP_PKEY_verify_recover` [BEHAVIOR]

- **Interestingness:** 6.5
- **Match score:** 0.8911 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Inferred roles:** control_heavy, validator
- **Size:** 492 -> 528 (+7.3%)
- **Blocks:** 23 -> 25 (+2)
- **Instructions:** 123 -> 132 (+9)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 26. `_ossl_sm2_internal_sign` [BEHAVIOR]

- **Interestingness:** 6.4
- **Match score:** 0.876 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 252 -> 300 (+19.0%)
- **Blocks:** 15 -> 18 (+3)
- **Instructions:** 63 -> 75 (+12)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 27. `_EVP_PKEY_sign` [BEHAVIOR]

- **Interestingness:** 5.9
- **Match score:** 0.8911 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 492 -> 528 (+7.3%)
- **Blocks:** 23 -> 25 (+2)
- **Instructions:** 123 -> 132 (+9)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence


---

### 28. `_kdf_hkdf_get_ctx_params` [REFACTOR]

- **Interestingness:** 5.6
- **Match score:** 0.8746 (similarity_bipartite)
- **Match uncertain** (close alternatives exist)
- **Triage confidence:** 0.0
- **Size:** 168 -> 228 (+35.7%)
- **Blocks:** 11 -> 13 (+2)
- **Instructions:** 42 -> 57 (+15)

**Heuristic Rationale:**
- Large size change (35.7%) without clear security signals


---

### 29. `_rev_body` [BEHAVIOR]

- **Interestingness:** 5.4
- **Match score:** 0.8447 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Size:** 1008 -> 1012 (+0.4%)
- **Blocks:** 66 -> 67 (+1)
- **Instructions:** 252 -> 253 (+1)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_sleep`

---

### 30. `_www_body` [BEHAVIOR]

- **Interestingness:** 5.4
- **Match score:** 0.8715 (similarity_bipartite)
- **Triage confidence:** 0.0
- **Inferred roles:** control_heavy, validator
- **Size:** 2812 -> 2816 (+0.1%)
- **Blocks:** 184 -> 185 (+1)
- **Instructions:** 703 -> 704 (+1)

**Heuristic Rationale:**
- Meaningful structural or call-flow change without direct security evidence

  Ext calls added: `_sleep`

---

## Unmatched Functions

### New in B (12)
- `_ssl_session_dup_intern`
- `_bio_wait`
- `_ossl_bn_mask_bits_fixed_top`
- `_ossl_bn_is_word_fixed_top`
- `_ossl_bn_priv_rand_range_fixed_top`
- `_BN_sqr`
- `_dsa_precheck_params`
- `_EVP_PKEY_CTX_add1_hkdf_info`
- `_kdf_get_ctx_params`
- `_kdf_scrypt_settable_ctx_params`
- `_kdf_tls1_prf_settable_ctx_params`
- `_blake2_mac_settable_ctx_params`
