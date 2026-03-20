"""Function matching between two feature sets."""

import math
from dataclasses import dataclass

from scipy.optimize import linear_sum_assignment

from .features import enrich_feature_set
from .normalize import normalize_symbol


@dataclass
class MatchResult:
    name_a: str
    name_b: str
    entry_a: str
    entry_b: str
    score: float
    method: str  # how the match was found
    uncertain: bool = False
    index_a: int = -1
    index_b: int = -1  # internal; used for post-pass repair, omitted from JSON


def _jaccard(a: set, b: set) -> float:
    if not a and not b:
        return 1.0
    inter = len(a & b)
    union = len(a | b)
    return inter / union if union else 0.0


def _cosine_hist(a: dict, b: dict) -> float:
    """Cosine similarity between two count dicts."""
    keys = set(a) | set(b)
    if not keys:
        return 1.0
    dot = sum(a.get(k, 0) * b.get(k, 0) for k in keys)
    norm_a = math.sqrt(sum(v * v for v in a.values()))
    norm_b = math.sqrt(sum(v * v for v in b.values()))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


def _size_penalty(size_a: int, size_b: int) -> float:
    """Penalty factor for size difference. 1.0 = same size, approaches 0 for huge diff."""
    if size_a == 0 and size_b == 0:
        return 1.0
    ratio = min(size_a, size_b) / max(size_a, size_b) if max(size_a, size_b) > 0 else 0
    return ratio


def _get_call_names(func: dict, external_only: bool = False) -> set[str]:
    names = set()
    for c in func.get("called_functions", []):
        if external_only and not c.get("is_external", False):
            continue
        names.add(c["name"])
    return names


def _name_similarity(fa: dict, fb: dict, stripped: bool) -> float:
    if stripped:
        return 0.0
    na = normalize_symbol(fa.get("name", ""))
    nb = normalize_symbol(fb.get("name", ""))
    if not na or not nb or na.startswith("fun_") or nb.startswith("fun_"):
        return 0.0
    return 1.0 if na == nb else 0.0


def _ratio_sim(a: int, b: int) -> float:
    if a == 0 and b == 0:
        return 1.0
    if max(a, b) == 0:
        return 0.0
    return min(a, b) / max(a, b)


def _update_top2(slot: list[tuple[float, int]], score: float, other_idx: int):
    """Track the two best scores and their paired indices for a row/column."""
    if score > slot[0][0]:
        if other_idx != slot[0][1]:
            slot[1] = slot[0]
        slot[0] = (score, other_idx)
    elif other_idx != slot[0][1] and score > slot[1][0]:
        slot[1] = (score, other_idx)


def compute_similarity(fa: dict, fb: dict, *, stripped: bool = False) -> float:
    """Compute weighted similarity score between two function feature dicts."""
    name_sim = _name_similarity(fa, fb, stripped)

    # String similarity
    strings_a = set(fa.get("normalized_strings", fa.get("strings", [])))
    strings_b = set(fb.get("normalized_strings", fb.get("strings", [])))
    str_sim = _jaccard(strings_a, strings_b)
    str_cat_sim = _jaccard(set(fa.get("string_categories", [])), set(fb.get("string_categories", [])))

    # Import/call similarity
    calls_a = _get_call_names(fa)
    calls_b = _get_call_names(fb)
    call_sim = _jaccard(calls_a, calls_b)

    # External call similarity (stronger signal)
    ext_a = _get_call_names(fa, external_only=True)
    ext_b = _get_call_names(fb, external_only=True)
    ext_sim = _jaccard(ext_a, ext_b)

    # Mnemonic histogram cosine
    mnem_sim = _cosine_hist(fa.get("mnemonic_hist", {}), fb.get("mnemonic_hist", {}))
    group_sim = _cosine_hist(fa.get("instruction_groups", {}), fb.get("instruction_groups", {}))

    # Mnemonic bigram Jaccard
    bg_a = set(fa.get("mnemonic_bigrams", {}).keys())
    bg_b = set(fb.get("mnemonic_bigrams", {}).keys())
    bigram_sim = _jaccard(bg_a, bg_b)

    # Size penalty
    size_pen = _size_penalty(fa.get("size", 0), fb.get("size", 0))

    # Block count similarity
    ba, bb = fa.get("block_count", 1), fb.get("block_count", 1)
    block_sim = _size_penalty(ba, bb)

    api_family_sim = _jaccard(set(fa.get("api_families", [])), set(fb.get("api_families", [])))
    const_bucket_sim = _jaccard(set(fa.get("constant_buckets", [])), set(fb.get("constant_buckets", [])))
    role_sim = _jaccard(set(fa.get("function_roles", [])), set(fb.get("function_roles", [])))

    ctx_a = fa.get("callgraph_context", {})
    ctx_b = fb.get("callgraph_context", {})
    ctx_sim = (
        _ratio_sim(ctx_a.get("caller_count", 0), ctx_b.get("caller_count", 0))
        + _ratio_sim(ctx_a.get("callee_count", 0), ctx_b.get("callee_count", 0))
        + _ratio_sim(ctx_a.get("external_callee_count", 0), ctx_b.get("external_callee_count", 0))
    ) / 3.0

    # Weighted combination
    score = (
        0.15 * name_sim
        + 0.12 * str_sim
        + 0.08 * str_cat_sim
        + 0.10 * ext_sim
        + 0.08 * call_sim
        + 0.14 * mnem_sim
        + 0.08 * group_sim
        + 0.05 * bigram_sim
        + 0.05 * api_family_sim
        + 0.06 * role_sim
        + 0.04 * const_bucket_sim
        + 0.05 * ctx_sim
        + 0.025 * size_pen
        + 0.025 * block_sim
    )
    return score


def _is_plausible_rename(name_a: str, name_b: str) -> bool:
    """Check if two function names could plausibly be renames of each other."""
    na = normalize_symbol(name_a).lower()
    nb = normalize_symbol(name_b).lower()
    if na == nb:
        return True
    # Strip underscores to catch snake_case ↔ camelCase (usage_advanced → usageAdvanced)
    na_flat = na.replace("_", "")
    nb_flat = nb.replace("_", "")
    if na_flat == nb_flat:
        return True
    # One is a substring of the other (e.g. foo → foo_internal)
    if na in nb or nb in na:
        return True
    min_len = min(len(na), len(nb))
    max_len = max(len(na), len(nb))
    if min_len >= 6:
        # Share a significant common prefix (e.g. ZSTD_compress... variants)
        # Use max_len to avoid matching short namespace prefixes (kex_, kdf_)
        prefix_len = 0
        for ca, cb in zip(na, nb):
            if ca != cb:
                break
            prefix_len += 1
        if prefix_len >= max_len * 0.4 and prefix_len >= 6:
            return True
        # Share a significant common suffix (e.g. ...BufferPool variants)
        # Use stricter threshold than prefix — common suffixes like _handler,
        # _init, _free would otherwise cause false matches.
        suffix_len = 0
        for ca, cb in zip(reversed(na), reversed(nb)):
            if ca != cb:
                break
            suffix_len += 1
        max_len = max(len(na), len(nb))
        if suffix_len >= 10 and suffix_len >= max_len * 0.4:
            return True
    return False


def _has_plausible_rename(name: str, candidate_names: set[str]) -> bool:
    """Check if any candidate name is a plausible rename of the given name."""
    return any(_is_plausible_rename(name, cn) for cn in candidate_names)


# Pass 2: when both functions have real (non-FUN_) names that are not plausible
# renames, require at least this similarity.  Cuts bogus edges like
# ``_EVP_PKEY_CTX_set1_scrypt_salt`` ↔ ``_kdf_hkdf_settable_ctx_params`` that
# only meet the default threshold on structural coincidence.
CROSS_NAME_MIN_SIMILARITY = 0.52


def _is_synthetic_symbol_name(name: str) -> bool:
    return name.startswith("FUN_") or name.startswith("thunk_FUN_")


def _cross_name_similarity_floor_applies(fa: dict, fb: dict, *, stripped: bool) -> bool:
    """If True, the (fa, fb) edge needs max(threshold, CROSS_NAME_MIN_SIMILARITY)."""
    if stripped:
        return False
    na = fa.get("name") or ""
    nb = fb.get("name") or ""
    if _is_synthetic_symbol_name(na) or _is_synthetic_symbol_name(nb):
        return False
    return not _is_plausible_rename(na, nb)


def _repair_exact_b_name_mismatches(
    matches: list[MatchResult],
    used_a: set[int],
    used_b: set[int],
    funcs_a: list,
    funcs_b: list,
    *,
    stripped: bool,
) -> None:
    """Fix absurd bipartite pairings using leftover exact names on B.

    ``linear_sum_assignment`` optimizes *global* sum, so row A can be paired
    with a wrong B column while a different B row still carries A's symbol
    name (unmatched) — e.g. duplicate A-side entries consuming the only
    same-name B slot in pass 1, or size blocking so the real same-name B
    never entered the similarity matrix.  Reassign when exactly one unmatched
    B function has ``name == name_a``.
    """
    max_iter = min(len(matches) + 8, 64)
    for _ in range(max_iter):
        unmatched_b_by_name: dict[str, list[int]] = {}
        for j in range(len(funcs_b)):
            if j in used_b:
                continue
            nm = funcs_b[j]["name"]
            if nm.startswith("FUN_") or nm.startswith("thunk_FUN_"):
                continue
            unmatched_b_by_name.setdefault(nm, []).append(j)

        candidates = [
            m
            for m in matches
            if m.index_a >= 0
            and m.index_b >= 0
            and not funcs_a[m.index_a]["name"].startswith("FUN_")
            and not funcs_a[m.index_a]["name"].startswith("thunk_FUN_")
            and funcs_a[m.index_a]["name"] != funcs_b[m.index_b]["name"]
        ]
        if not candidates:
            break
        candidates.sort(key=lambda m: m.score)

        changed = False
        for m in candidates:
            na = funcs_a[m.index_a]["name"]
            js = unmatched_b_by_name.get(na, [])
            if len(js) != 1:
                continue
            j_new = js[0]
            j_old = m.index_b
            if j_new == j_old:
                continue

            used_b.remove(j_old)
            used_b.add(j_new)
            fb = funcs_b[j_new]
            m.name_b = fb["name"]
            m.entry_b = fb["entry"]
            m.index_b = j_new
            m.score = compute_similarity(funcs_a[m.index_a], fb, stripped=stripped)
            m.method = "name_repair_unmatched_b"
            m.uncertain = False

            unmatched_b_by_name[na].remove(j_new)
            if not unmatched_b_by_name[na]:
                del unmatched_b_by_name[na]
            changed = True
            break

        if not changed:
            break


def match_functions(features_a: dict, features_b: dict,
                    threshold: float = 0.3,
                    uncertain_gap: float = 0.05,
                    stripped: bool = False) -> dict:
    """Match functions between two binaries.

    Returns a dict with:
      - matches: list of matched pairs with scores
      - unmatched_a: functions only in A
      - unmatched_b: functions only in B
    """
    features_a = enrich_feature_set(features_a)
    features_b = enrich_feature_set(features_b)
    funcs_a = features_a["functions"]
    funcs_b = features_b["functions"]

    # Build name index for exact-name matching
    name_idx_b = {}
    for i, f in enumerate(funcs_b):
        name_idx_b.setdefault(f["name"], []).append(i)

    matches: list[MatchResult] = []
    used_a: set[int] = set()
    used_b: set[int] = set()

    if not stripped:
        # --- Pass 1: exact name match (non-default names) ---
        for i, fa in enumerate(funcs_a):
            name = fa["name"]
            if name.startswith("FUN_") or name.startswith("thunk_FUN_"):
                continue
            if name in name_idx_b:
                candidates = [j for j in name_idx_b[name] if j not in used_b]
                if len(candidates) == 1:
                    j = candidates[0]
                    score = compute_similarity(fa, funcs_b[j], stripped=stripped)
                    matches.append(MatchResult(
                        name_a=fa["name"], name_b=funcs_b[j]["name"],
                        entry_a=fa["entry"], entry_b=funcs_b[j]["entry"],
                        score=score, method="name_exact",
                        index_a=i, index_b=j,
                    ))
                    used_a.add(i)
                    used_b.add(j)
                elif len(candidates) > 1:
                    # Multiple same-named candidates: pick the best by similarity
                    best_j, best_score = -1, -1.0
                    for j in candidates:
                        s = compute_similarity(fa, funcs_b[j], stripped=stripped)
                        if s > best_score:
                            best_score = s
                            best_j = j
                    if best_j >= 0:
                        matches.append(MatchResult(
                            name_a=fa["name"], name_b=funcs_b[best_j]["name"],
                            entry_a=fa["entry"], entry_b=funcs_b[best_j]["entry"],
                            score=best_score, method="name_exact_multi",
                            index_a=i, index_b=best_j,
                        ))
                        used_a.add(i)
                        used_b.add(best_j)

    # --- Pass 1.5: exclude named functions with no plausible counterpart ---
    # When a symbolized function exists in A but not B (or vice versa), check
    # if any remaining name in the other side is a plausible rename.  If not,
    # the function was definitively removed/added — exclude it from the
    # similarity pass so it doesn't get force-paired with unrelated code.
    name_only_a: set[int] = set()  # indices definitively only in A
    name_only_b: set[int] = set()  # indices definitively only in B
    if not stripped:
        name_idx_a = {}
        for i, f in enumerate(funcs_a):
            name_idx_a.setdefault(f["name"], []).append(i)

        # Collect remaining (unmatched) names on each side for rename checks
        remaining_names_b = set()
        for j, fb in enumerate(funcs_b):
            if j not in used_b:
                name = fb["name"]
                if not name.startswith("FUN_") and not name.startswith("thunk_FUN_"):
                    remaining_names_b.add(name)

        remaining_names_a = set()
        for i, fa in enumerate(funcs_a):
            if i not in used_a:
                name = fa["name"]
                if not name.startswith("FUN_") and not name.startswith("thunk_FUN_"):
                    remaining_names_a.add(name)

        for i, fa in enumerate(funcs_a):
            if i in used_a:
                continue
            name = fa["name"]
            if name.startswith("FUN_") or name.startswith("thunk_FUN_"):
                continue
            if name not in name_idx_b:
                if not _has_plausible_rename(name, remaining_names_b):
                    name_only_a.add(i)

        for j, fb in enumerate(funcs_b):
            if j in used_b:
                continue
            name = fb["name"]
            if name.startswith("FUN_") or name.startswith("thunk_FUN_"):
                continue
            if name not in name_idx_a:
                if not _has_plausible_rename(name, remaining_names_a):
                    name_only_b.add(j)

    # --- Pass 2: similarity-based matching for remaining functions ---
    skip_a = used_a | name_only_a
    skip_b = used_b | name_only_b
    remaining_a = [(i, f) for i, f in enumerate(funcs_a) if i not in skip_a]
    remaining_b = [(j, f) for j, f in enumerate(funcs_b) if j not in skip_b]

    large_match = len(remaining_a) * len(remaining_b) >= 100000
    if large_match:
        mode = "stripped structural mode" if stripped else "hybrid name+similarity mode"
        print(
            f"Building candidate match matrix in {mode}: "
            f"{len(remaining_a)} x {len(remaining_b)} remaining functions...",
            flush=True,
        )

    # Size-based blocking: only compare if sizes are within 3x
    scored_pairs: list[tuple[float, int, int]] = []
    for idx, (i, fa) in enumerate(remaining_a, 1):
        if large_match and (idx == 1 or idx % 100 == 0 or idx == len(remaining_a)):
            print(f"  candidate pass: {idx}/{len(remaining_a)} source functions", flush=True)
        sa = fa.get("size", 0)
        for j, fb in remaining_b:
            sb = fb.get("size", 0)
            if sa > 0 and sb > 0:
                ratio = min(sa, sb) / max(sa, sb)
                if ratio < 0.33:
                    continue
            if fa.get("api_families") and fb.get("api_families"):
                if not (set(fa.get("api_families", [])) & set(fb.get("api_families", []))):
                    if ratio < 0.5:
                        continue
            score = compute_similarity(fa, fb, stripped=stripped)
            eff_threshold = threshold
            if _cross_name_similarity_floor_applies(fa, fb, stripped=stripped):
                eff_threshold = max(threshold, CROSS_NAME_MIN_SIMILARITY)
            if score >= eff_threshold:
                scored_pairs.append((score, i, j))

    if large_match:
        print(f"Solving bipartite assignment over {len(scored_pairs)} candidate pairs...", flush=True)

    if scored_pairs:
        row_index = {i: idx for idx, (i, _) in enumerate(remaining_a)}
        col_index = {j: idx for idx, (j, _) in enumerate(remaining_b)}
        score_matrix = [[0.0 for _ in remaining_b] for _ in remaining_a]
        row_top2 = [[(0.0, -1), (0.0, -1)] for _ in remaining_a]
        col_top2 = [[(0.0, -1), (0.0, -1)] for _ in remaining_b]
        for score, i, j in scored_pairs:
            row = row_index[i]
            col = col_index[j]
            score_matrix[row][col] = score
            _update_top2(row_top2[row], score, col)
            _update_top2(col_top2[col], score, row)

        rows, cols = linear_sum_assignment([[-score for score in row] for row in score_matrix])
        if large_match:
            print(f"Finalizing {len(rows)} proposed assignments...", flush=True)
        for row, col in zip(rows, cols):
            score = score_matrix[row][col]
            fa = remaining_a[row][1]
            fb = remaining_b[col][1]
            eff_threshold = threshold
            if _cross_name_similarity_floor_applies(fa, fb, stripped=stripped):
                eff_threshold = max(threshold, CROSS_NAME_MIN_SIMILARITY)
            if score < eff_threshold:
                continue
            i = remaining_a[row][0]
            j = remaining_b[col][0]
            if i in used_a or j in used_b:
                continue

            row_best = row_top2[row]
            col_best = col_top2[col]
            alt_row = row_best[1][0] if row_best[0][1] == col else row_best[0][0]
            alt_col = col_best[1][0] if col_best[0][1] == row else col_best[0][0]
            second_best = max(alt_row, alt_col)
            uncertain = bool(second_best and score - second_best < uncertain_gap)

            matches.append(MatchResult(
                name_a=funcs_a[i]["name"], name_b=funcs_b[j]["name"],
                entry_a=funcs_a[i]["entry"], entry_b=funcs_b[j]["entry"],
                score=score,
                method="similarity_bipartite",
                uncertain=uncertain,
                index_a=i,
                index_b=j,
            ))
            used_a.add(i)
            used_b.add(j)

    _repair_exact_b_name_mismatches(
        matches, used_a, used_b, funcs_a, funcs_b, stripped=stripped
    )

    unmatched_a = [funcs_a[i]["name"] for i in range(len(funcs_a)) if i not in used_a]
    unmatched_b = [funcs_b[j]["name"] for j in range(len(funcs_b)) if j not in used_b]
    # name_only sets are already excluded from used_a/used_b, so they appear here

    return {
        "binary_a": features_a.get("binary", "A"),
        "binary_b": features_b.get("binary", "B"),
        "num_matches": len(matches),
        "num_unmatched_a": len(unmatched_a),
        "num_unmatched_b": len(unmatched_b),
        "matches": [
            {
                "name_a": m.name_a, "name_b": m.name_b,
                "entry_a": m.entry_a, "entry_b": m.entry_b,
                "score": round(m.score, 4),
                "method": m.method,
                "uncertain": m.uncertain,
            }
            for m in matches
        ],
        "unmatched_a": unmatched_a,
        "unmatched_b": unmatched_b,
    }
