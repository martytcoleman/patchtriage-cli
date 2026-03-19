"""Native symbolized extraction backend using nm/objdump/otool."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter

from .classify import classify_binary
from .features import enrich_feature_set


def _run_text(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return result.stdout
    except Exception:
        return ""


def _source_metadata(binary_path: str) -> dict:
    stat = os.stat(binary_path)
    return {
        "path": os.path.abspath(binary_path),
        "size": stat.st_size,
        "mtime": int(stat.st_mtime),
    }


def _load_cached(output_path: str, binary_path: str) -> dict | None:
    if not os.path.isfile(output_path):
        return None
    try:
        with open(output_path) as f:
            data = json.load(f)
    except Exception:
        return None
    if data.get("source_metadata") == _source_metadata(binary_path):
        return data
    return None


def _detect_arch(binary_path: str) -> str:
    out = _run_text(["file", "-b", binary_path]).lower()
    if "arm64" in out or "aarch64" in out:
        return "aarch64"
    if "x86-64" in out or "x86_64" in out:
        return "x86_64"
    if "80386" in out or "i386" in out:
        return "x86"
    return "unknown"


def _extract_imports(binary_path: str) -> list[str]:
    out = _run_text(["nm", "-an", binary_path])
    imports = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0] == "U":
            imports.append(parts[1])
        elif len(parts) >= 3 and parts[1] == "U":
            imports.append(parts[2])
    return sorted(set(imports))


def _extract_text_symbols(binary_path: str) -> list[dict]:
    out = _run_text(["nm", "-an", binary_path])
    symbols = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in {"T", "t"}:
            addr, _, name = parts[:3]
            if name == "__mh_execute_header":
                continue
            symbols.append({"name": name, "entry": addr})
    return symbols


def _parse_disassembly(binary_path: str, fmt: str) -> dict[str, dict]:
    if fmt == "macho":
        out = _run_text(["objdump", "--macho", "--disassemble", binary_path])
    else:
        out = _run_text(["objdump", "-d", binary_path])

    functions: dict[str, dict] = {}
    current = None
    label_re = re.compile(r"^([_$A-Za-z][\w$.@+-]*):$")
    elf_label_re = re.compile(r"^[0-9a-fA-F]+\s+<([^>]+)>:$")

    for raw in out.splitlines():
        line = raw.rstrip()
        m = label_re.match(line)
        if not m:
            m = elf_label_re.match(line)
        if m:
            name = m.group(1)
            current = functions.setdefault(name, {
                "mnemonic_hist": Counter(),
                "mnemonic_bigrams": Counter(),
                "strings": [],
                "constants": set(),
                "called_functions": [],
                "block_count": 1,
                "instr_count": 0,
                "_prev": None,
            })
            continue
        if current is None:
            continue
        mnemonic = _parse_mnemonic(line)
        if not mnemonic:
            continue
        current["mnemonic_hist"][mnemonic] += 1
        current["instr_count"] += 1
        if current["_prev"] is not None:
            current["mnemonic_bigrams"][f"{current['_prev']},{mnemonic}"] += 1
        current["_prev"] = mnemonic
        if _is_branch(mnemonic):
            current["block_count"] += 1

        target = _parse_call_target(line)
        if target:
            current["called_functions"].append(target)
        for const in _parse_constants(line):
            current["constants"].add(const)
        string_value = _parse_literal_string(line)
        if string_value and string_value not in current["strings"]:
            current["strings"].append(string_value)

    for data in functions.values():
        data.pop("_prev", None)
    return functions


def _parse_mnemonic(line: str) -> str | None:
    if ":" not in line or "\t" not in line:
        return None
    _, rest = line.split(":", 1)
    parts = [part.strip() for part in rest.split("\t") if part.strip()]
    for part in parts:
        candidate = part.split()[0].lower()
        if re.fullmatch(r"[0-9a-f]+", candidate):
            continue
        if re.fullmatch(r"[a-z][a-z0-9._]*", candidate):
            return candidate
    return None


def _is_branch(mnemonic: str) -> bool:
    return (
        mnemonic.startswith("b")
        or mnemonic.startswith("j")
        or mnemonic in {"call", "ret", "bl", "blr"}
    )


def _parse_call_target(line: str) -> dict | None:
    if "symbol stub for:" in line:
        name = line.split("symbol stub for:", 1)[1].strip()
        return {"name": name, "is_external": True, "entry": None}
    if "\tcall" in line or "\tbl" in line or "\tblr" in line:
        m = re.search(r"<([^>]+)>", line)
        if m:
            name = m.group(1)
            return {"name": name, "is_external": False, "entry": None}
        m = re.search(r"0x([0-9a-fA-F]+)", line)
        if m:
            return {"name": f"sub_{m.group(1)}", "is_external": False, "entry": m.group(1)}
    return None


def _parse_constants(line: str) -> list[int]:
    values = []
    for m in re.finditer(r"#?0x([0-9a-fA-F]+)", line):
        try:
            values.append(int(m.group(1), 16))
        except Exception:
            pass
    return values


def _parse_literal_string(line: str) -> str | None:
    if "literal pool for:" in line:
        return line.split("literal pool for:", 1)[1].strip().strip('"')
    return None


def run_native_extract(binary_path: str, output_path: str, reuse_cached: bool = True) -> dict:
    """Extract function-level features from symbolized binaries without Ghidra."""
    binary_path = os.path.abspath(binary_path)
    output_path = os.path.abspath(output_path)

    if reuse_cached:
        cached = _load_cached(output_path, binary_path)
        if cached is not None:
            print(f"Reusing cached native features from {output_path}")
            return cached

    info = classify_binary(binary_path)
    symbols = _extract_text_symbols(binary_path)
    imports = _extract_imports(binary_path)
    disassembly = _parse_disassembly(binary_path, info["format"])

    functions = []
    for sym in symbols:
        name = sym["name"]
        parsed = disassembly.get(name, {})
        functions.append({
            "name": name,
            "entry": sym["entry"],
            "size": max(parsed.get("instr_count", 0), 1) * 4,
            "instr_count": parsed.get("instr_count", 0),
            "block_count": parsed.get("block_count", 1),
            "mnemonic_hist": dict(parsed.get("mnemonic_hist", {})),
            "mnemonic_bigrams": dict(parsed.get("mnemonic_bigrams", {})),
            "strings": parsed.get("strings", []),
            "constants": sorted(parsed.get("constants", [])),
            "called_functions": parsed.get("called_functions", []),
            "callers": [],
        })

    data = enrich_feature_set({
        "binary": binary_path,
        "arch": _detect_arch(binary_path),
        "num_functions": len(functions),
        "functions": functions,
    })
    data["source_metadata"] = _source_metadata(binary_path)
    data["analysis_profile"] = "native"
    data["classification"] = info
    data["backend"] = "native"
    data["imports"] = imports

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(
        f"Native extraction summary: {len(symbols)} symbols, "
        f"{len(imports)} imports, {len(disassembly)} disassembled functions"
    )
    print(f"Extracted {data['num_functions']} native functions -> {output_path}")
    return data
