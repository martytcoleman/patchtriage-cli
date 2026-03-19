"""Cheap binary pre-scan classification for adaptive PatchTriage behavior."""

from __future__ import annotations

import os
import subprocess


MACHO_MAGICS = {
    b"\xfe\xed\xfa\xce",
    b"\xce\xfa\xed\xfe",
    b"\xfe\xed\xfa\xcf",
    b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe",
    b"\xbe\xba\xfe\xca",
}


def _read_prefix(path: str, limit: int = 2 * 1024 * 1024) -> bytes:
    with open(path, "rb") as f:
        return f.read(limit)


def classify_binary(path: str) -> dict:
    """Return cheap metadata and a recommended analysis profile."""
    size = os.path.getsize(path)
    prefix = _read_prefix(path)
    magic = prefix[:4]
    fmt = "unknown"
    arch = "unknown"
    reasons: list[str] = []

    if magic in MACHO_MAGICS:
        fmt = "macho"
    elif magic == b"\x7fELF":
        fmt = "elf"
    elif magic[:2] == b"MZ":
        fmt = "pe"

    language = "unknown"
    lower = prefix.lower()
    if b"go buildinf:" in prefix or b"runtime." in prefix or b"type.." in prefix:
        language = "go"
        reasons.append("Go build/runtime markers detected")
    elif any(marker in lower for marker in (b"rustc", b"core::", b"alloc::", b"panicked at", b"std::")):
        language = "rust"
        reasons.append("Rust symbol/string markers detected")

    if size >= 8 * 1024 * 1024:
        reasons.append(f"large binary ({size / (1024 * 1024):.1f} MiB)")

    challenging = size >= 8 * 1024 * 1024 or language in {"go", "rust"}
    profile = "fast" if challenging else "full"
    if challenging and not reasons:
        reasons.append("large or complex binary")
    text_symbol_count = _count_text_symbols(path)
    symbolized = text_symbol_count >= 3

    return {
        "path": os.path.abspath(path),
        "format": fmt,
        "arch": arch,
        "language": language,
        "size_bytes": size,
        "symbolized": symbolized,
        "text_symbol_count": text_symbol_count,
        "challenging": challenging,
        "recommended_profile": profile,
        "reasons": reasons,
    }


def _count_text_symbols(path: str) -> int:
    try:
        result = subprocess.run(
            ["nm", "-an", path],
            capture_output=True,
            text=True,
            check=True,
        )
    except Exception:
        return 0
    count = 0
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[1] in {"T", "t"}:
            count += 1
    return count
