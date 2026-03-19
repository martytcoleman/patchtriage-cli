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
                candidates = name_idx_b[name]
                if len(candidates) == 1:
                    j = candidates[0]
                    if j not in used_b:
                        score = compute_similarity(fa, funcs_b[j], stripped=stripped)
                        matches.append(MatchResult(
                            name_a=fa["name"], name_b=funcs_b[j]["name"],
                            entry_a=fa["entry"], entry_b=funcs_b[j]["entry"],
                            score=score, method="name_exact",
                        ))
                        used_a.add(i)
                        used_b.add(j)

    # --- Pass 2: similarity-based matching for remaining functions ---
    remaining_a = [(i, f) for i, f in enumerate(funcs_a) if i not in used_a]
    remaining_b = [(j, f) for j, f in enumerate(funcs_b) if j not in used_b]

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
            if score >= threshold:
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
            if score < threshold:
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
            ))
            used_a.add(i)
            used_b.add(j)

    unmatched_a = [funcs_a[i]["name"] for i in range(len(funcs_a)) if i not in used_a]
    unmatched_b = [funcs_b[j]["name"] for j in range(len(funcs_b)) if j not in used_b]

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
