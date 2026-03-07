"""Function matching between two feature sets."""

import json
import math
from collections import Counter
from dataclasses import dataclass, field


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


def compute_similarity(fa: dict, fb: dict) -> float:
    """Compute weighted similarity score between two function feature dicts."""
    # String similarity
    strings_a = set(fa.get("strings", []))
    strings_b = set(fb.get("strings", []))
    str_sim = _jaccard(strings_a, strings_b)

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

    # Mnemonic bigram Jaccard
    bg_a = set(fa.get("mnemonic_bigrams", {}).keys())
    bg_b = set(fb.get("mnemonic_bigrams", {}).keys())
    bigram_sim = _jaccard(bg_a, bg_b)

    # Size penalty
    size_pen = _size_penalty(fa.get("size", 0), fb.get("size", 0))

    # Block count similarity
    ba, bb = fa.get("block_count", 1), fb.get("block_count", 1)
    block_sim = _size_penalty(ba, bb)

    # Weighted combination
    score = (
        0.20 * str_sim
        + 0.15 * ext_sim
        + 0.15 * call_sim
        + 0.20 * mnem_sim
        + 0.10 * bigram_sim
        + 0.10 * size_pen
        + 0.10 * block_sim
    )
    return score


def match_functions(features_a: dict, features_b: dict,
                    threshold: float = 0.3,
                    uncertain_gap: float = 0.05) -> dict:
    """Match functions between two binaries.

    Returns a dict with:
      - matches: list of matched pairs with scores
      - unmatched_a: functions only in A
      - unmatched_b: functions only in B
    """
    funcs_a = features_a["functions"]
    funcs_b = features_b["functions"]

    # Build name index for exact-name matching
    name_idx_b = {}
    for i, f in enumerate(funcs_b):
        name_idx_b.setdefault(f["name"], []).append(i)

    matches: list[MatchResult] = []
    used_a: set[int] = set()
    used_b: set[int] = set()

    # --- Pass 1: exact name match (non-default names) ---
    for i, fa in enumerate(funcs_a):
        name = fa["name"]
        if name.startswith("FUN_") or name.startswith("thunk_FUN_"):
            continue  # auto-generated name, skip
        if name in name_idx_b:
            candidates = name_idx_b[name]
            if len(candidates) == 1:
                j = candidates[0]
                if j not in used_b:
                    score = compute_similarity(fa, funcs_b[j])
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

    # Size-based blocking: only compare if sizes are within 3x
    scored_pairs: list[tuple[float, int, int]] = []
    for i, fa in remaining_a:
        sa = fa.get("size", 0)
        for j, fb in remaining_b:
            sb = fb.get("size", 0)
            if sa > 0 and sb > 0:
                ratio = min(sa, sb) / max(sa, sb)
                if ratio < 0.33:
                    continue
            score = compute_similarity(fa, fb)
            if score >= threshold:
                scored_pairs.append((score, i, j))

    # Greedy assignment: highest score first
    scored_pairs.sort(reverse=True)
    for score, i, j in scored_pairs:
        if i in used_a or j in used_b:
            continue
        # Check uncertainty: is the second-best close?
        uncertain = False
        for score2, i2, j2 in scored_pairs:
            if score2 >= score:
                continue
            if (i2 == i and j2 != j) or (j2 == j and i2 != i):
                if score - score2 < uncertain_gap:
                    uncertain = True
                break

        matches.append(MatchResult(
            name_a=funcs_a[i]["name"], name_b=funcs_b[j]["name"],
            entry_a=funcs_a[i]["entry"], entry_b=funcs_b[j]["entry"],
            score=score,
            method="similarity",
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
