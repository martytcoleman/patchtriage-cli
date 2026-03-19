"""Normalization helpers for evidence-driven binary patch triage."""

from __future__ import annotations

import re


API_FAMILY_RULES: dict[str, tuple[str, ...]] = {
    "string": ("str", "snprintf", "sprintf", "vsnprintf", "vsprintf"),
    "memory": ("mem", "alloc", "free", "realloc"),
    "file": ("fopen", "fclose", "fread", "fwrite", "fprintf", "open", "read", "write"),
    "network": ("socket", "bind", "listen", "accept", "connect", "recv", "send"),
    "process": ("exec", "fork", "wait", "system", "popen"),
    "crypto": ("crypto", "ssl", "tls", "hash", "aes", "sha", "rsa", "md5"),
    "auth": ("auth", "login", "passwd", "token", "credential"),
    "validation": ("check", "validate", "verify", "guard", "sanitize"),
}

STRING_CATEGORY_PATTERNS: dict[str, tuple[str, ...]] = {
    "error": ("error", "fail", "invalid", "panic", "bad", "reject", "denied"),
    "bounds": ("too long", "too large", "overflow", "underflow", "out of bounds", "limit"),
    "path": ("../", "..\\", "path", "directory", "file", "http://", "https://", "/"),
    "format": ("%s", "%d", "%x", "{", "}"),
    "http": ("http", "header", "content-length", "host:", "get ", "post "),
}

INSTR_GROUPS: dict[str, tuple[str, ...]] = {
    "compare": ("cmp", "test", "cmn", "tst"),
    "branch": ("j", "b.", "cb", "tb", "jmp", "call", "bl", "ret"),
    "memory": ("mov", "lea", "ldr", "str", "ld", "st", "push", "pop"),
    "arithmetic": ("add", "sub", "mul", "div", "inc", "dec", "adc", "sbb"),
    "logic": ("and", "or", "xor", "not", "shl", "shr", "sar"),
}

ROLE_NAME_RULES: dict[str, tuple[str, ...]] = {
    "parser": ("parse", "decode", "lex", "scan", "token", "read_", "load_"),
    "validator": ("valid", "check", "verify", "guard", "sanitize"),
    "formatter": ("format", "print", "render", "dump", "show"),
    "logger": ("log", "trace", "debug", "warn", "error"),
    "allocator": ("alloc", "free", "malloc", "realloc", "new", "delete"),
    "io": ("read", "write", "open", "close", "send", "recv", "file", "http"),
    "dispatcher": ("main", "dispatch", "handle", "route", "process"),
    "codec": ("compress", "decompress", "encode", "decode", "hash", "seqstore"),
    "benchmark": ("bench", "bmk", "lorem", "datagen", "trace"),
}


def normalize_symbol(name: str) -> str:
    """Normalize symbol names across common compiler / platform variants."""
    n = name.lstrip("_")
    for suffix in ("_chk", "_s", "@plt"):
        if n.endswith(suffix):
            n = n[: -len(suffix)]
    return n.lower()


def bucket_constant(value: int) -> str:
    """Bucket constants to reduce compiler-noise sensitivity."""
    v = abs(int(value))
    if v <= 4:
        return "tiny"
    if v <= 16:
        return "small"
    if v <= 255:
        return "byte"
    if v <= 4096:
        return "pageish"
    if v <= 65535:
        return "u16"
    if v <= 0xFFFFFFFF:
        return "u32"
    return "huge"


def normalize_string(value: str) -> str:
    """Lower-case and scrub numbers / formatting noise from strings."""
    s = value.strip().lower()
    s = re.sub(r"\d+", "<num>", s)
    s = re.sub(r"\s+", " ", s)
    return s


def classify_string(value: str) -> set[str]:
    """Classify strings into high-level semantic categories."""
    normalized = normalize_string(value)
    categories = set()
    for category, needles in STRING_CATEGORY_PATTERNS.items():
        if any(needle in normalized for needle in needles):
            categories.add(category)
    return categories


def classify_api_family(name: str) -> str | None:
    """Assign an imported/called function to a coarse API family."""
    normalized = normalize_symbol(name)
    for family, prefixes in API_FAMILY_RULES.items():
        if normalized.startswith(prefixes) or any(prefix in normalized for prefix in prefixes):
            return family
    return None


def mnemonic_groups(hist: dict[str, int]) -> dict[str, int]:
    """Aggregate instruction histograms into stable semantic groups."""
    grouped = {key: 0 for key in INSTR_GROUPS}
    for mnemonic, count in hist.items():
        m = mnemonic.lower()
        for group, prefixes in INSTR_GROUPS.items():
            if m.startswith(prefixes):
                grouped[group] += count
                break
    return grouped


def infer_function_roles(func: dict) -> list[str]:
    """Infer coarse functional roles from names, strings, APIs, and instruction mix."""
    roles = set()
    name = normalize_symbol(func.get("name", ""))
    api_families = set(func.get("api_families", []))
    categories = set(func.get("string_categories", []))
    calls = set(func.get("normalized_call_names", []))
    strings = set(func.get("normalized_strings", []))
    instr = func.get("instruction_groups", {})

    for role, markers in ROLE_NAME_RULES.items():
        if any(marker in name for marker in markers):
            roles.add(role)

    if "validation" in api_families or {"error", "bounds"} & categories:
        roles.add("validator")
    if "format" in categories or "string" in api_families and any("%" in s for s in strings):
        roles.add("formatter")
    if "file" in api_families or "network" in api_families or "http" in categories or "path" in categories:
        roles.add("io")
    if "memory" in api_families:
        roles.add("allocator")
    if any(call in {"printf", "fprintf", "puts", "putchar", "snprintf", "sprintf"} for call in calls):
        roles.add("formatter")
    if any(call in {"syslog", "fprintf", "perror"} for call in calls) and {"error", "format"} & categories:
        roles.add("logger")
    if any(tag in name for tag in ("compress", "decompress", "deflate", "inflate", "huf", "fse", "zstd")):
        roles.add("codec")
    if instr.get("compare", 0) >= 2 and instr.get("branch", 0) >= 2 and ("validator" in roles or "parser" in roles):
        roles.add("control_heavy")
    if instr.get("memory", 0) >= 8 and "allocator" in roles:
        roles.add("memory_heavy")
    return sorted(roles)


def enrich_function_features(func: dict) -> dict:
    """Return a shallow copy of func with derived normalized features added."""
    enriched = dict(func)

    strings = enriched.get("strings", [])
    normalized_strings = sorted({normalize_string(s) for s in strings if s})
    string_categories = sorted({cat for s in strings for cat in classify_string(s)})

    constants = enriched.get("constants", [])
    constant_buckets = sorted({bucket_constant(v) for v in constants})

    calls = enriched.get("called_functions", [])
    api_families = sorted({
        family
        for call in calls
        for family in [classify_api_family(call.get("name", ""))]
        if family
    })

    call_names = [normalize_symbol(c.get("name", "")) for c in calls if c.get("name")]
    callers = [normalize_symbol(c) for c in enriched.get("callers", []) if c]
    hist = enriched.get("mnemonic_hist", {})
    instr_groups = mnemonic_groups(hist)

    enriched["normalized_strings"] = normalized_strings
    enriched["string_categories"] = string_categories
    enriched["constant_buckets"] = constant_buckets
    enriched["api_families"] = api_families
    enriched["normalized_call_names"] = sorted(set(call_names))
    enriched["normalized_callers"] = sorted(set(callers))
    enriched["instruction_groups"] = instr_groups
    enriched["callgraph_context"] = {
        "caller_count": len(callers),
        "callee_count": len(call_names),
        "external_callee_count": sum(1 for c in calls if c.get("is_external")),
        "internal_callee_count": sum(1 for c in calls if not c.get("is_external")),
    }
    roles = infer_function_roles(enriched)
    enriched["function_roles"] = roles
    enriched["primary_role"] = roles[0] if roles else "unknown"
    return enriched
