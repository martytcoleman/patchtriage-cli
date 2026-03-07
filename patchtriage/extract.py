"""Run Ghidra analysis via pyghidra and extract features from a binary."""

import json
import os
import sys
from collections import Counter
from pathlib import Path


def _find_ghidra_install() -> str:
    """Locate Ghidra install directory."""
    import glob
    candidates = [
        os.environ.get("GHIDRA_INSTALL_DIR", ""),
    ]
    candidates += glob.glob(os.path.expanduser("~/ghidra_*/"))
    candidates += glob.glob("/opt/ghidra*/")
    candidates += glob.glob("/Applications/ghidra*/")
    for c in candidates:
        if c and os.path.isdir(c):
            return c
    return ""


def _extract_features(program) -> dict:
    """Extract per-function features from a Ghidra FlatProgramAPI program."""
    from ghidra.program.model.block import BasicBlockModel
    from ghidra.util.task import ConsoleTaskMonitor

    monitor = ConsoleTaskMonitor()
    listing = program.getListing()
    func_mgr = program.getFunctionManager()
    bbm = BasicBlockModel(program)
    ref_mgr = program.getReferenceManager()

    functions_out = []

    for func in func_mgr.getFunctions(True):
        if func.isThunk():
            continue

        name = func.getName()
        entry = func.getEntryPoint().toString()
        body = func.getBody()

        # --- instruction-level features ---
        mnemonic_hist = Counter()
        bigrams = Counter()
        instr_count = 0
        constants = set()
        prev_mnemonic = None

        instr_iter = listing.getInstructions(body, True)
        while instr_iter.hasNext():
            instr = instr_iter.next()
            m = instr.getMnemonicString()
            mnemonic_hist[m] += 1
            instr_count += 1
            if prev_mnemonic is not None:
                bigrams[prev_mnemonic + "," + m] += 1
            prev_mnemonic = m
            # collect scalar operand constants
            for i in range(instr.getNumOperands()):
                for obj in instr.getOpObjects(i):
                    cls_name = type(obj).__name__
                    if cls_name in ("Scalar", "int", "long") or hasattr(obj, 'longValue'):
                        try:
                            v = int(obj.longValue()) if hasattr(obj, 'longValue') else int(obj)
                            if 2 <= abs(v) <= 0xFFFFFFFF:
                                constants.add(v)
                        except Exception:
                            pass

        # --- basic-block count ---
        block_count = 0
        block_iter = bbm.getCodeBlocksContaining(body, monitor)
        while block_iter.hasNext():
            block_iter.next()
            block_count += 1

        # --- referenced strings ---
        strings = []
        ref_iter = ref_mgr.getReferenceIterator(body.getMinAddress())
        while ref_iter.hasNext():
            ref = ref_iter.next()
            if not body.contains(ref.getFromAddress()):
                continue
            to_addr = ref.getToAddress()
            data = listing.getDataAt(to_addr)
            if data is not None and data.hasStringValue():
                s = data.getValue()
                if s and len(str(s)) >= 2:
                    strings.append(str(s))

        # --- called functions ---
        called_funcs = []
        called_set = func.getCalledFunctions(monitor)
        for cf in called_set:
            called_funcs.append({
                "name": cf.getName(),
                "is_external": cf.isExternal() or cf.isThunk(),
            })

        # --- calling functions ---
        callers = []
        caller_set = func.getCallingFunctions(monitor)
        for cf in caller_set:
            callers.append(cf.getName())

        func_data = {
            "name": name,
            "entry": entry,
            "size": int(body.getNumAddresses()),
            "instr_count": instr_count,
            "block_count": block_count,
            "mnemonic_hist": dict(mnemonic_hist),
            "mnemonic_bigrams": dict(bigrams),
            "strings": strings,
            "constants": list(constants),
            "called_functions": called_funcs,
            "callers": callers,
        }
        functions_out.append(func_data)

    return {
        "binary": str(program.getExecutablePath()),
        "arch": str(program.getLanguage().getProcessor()),
        "num_functions": len(functions_out),
        "functions": functions_out,
    }


def run_extract(binary_path: str, output_path: str, ghidra_path: str | None = None) -> dict:
    """Run Ghidra via pyghidra to extract features from binary_path into output_path.

    Returns the parsed features dict.
    """
    binary_path = os.path.abspath(binary_path)
    output_path = os.path.abspath(output_path)

    if not os.path.isfile(binary_path):
        print(f"Error: binary not found: {binary_path}", file=sys.stderr)
        sys.exit(1)

    ghidra_install = ghidra_path or _find_ghidra_install()
    if not ghidra_install:
        print(
            "Error: cannot find Ghidra. Set GHIDRA_INSTALL_DIR env var.",
            file=sys.stderr,
        )
        sys.exit(1)

    try:
        import pyghidra
    except ImportError:
        print("Error: pyghidra not installed. Run: pip install pyghidra", file=sys.stderr)
        sys.exit(1)

    print(f"Running Ghidra analysis on {binary_path} ...")

    pyghidra.start(ghidra_install)

    with pyghidra.open_program(binary_path) as flat_api:
        program = flat_api.getCurrentProgram()
        data = _extract_features(program)

    with open(output_path, "w") as f:
        json.dump(data, f, indent=2, default=str)

    print(f"Extracted {data['num_functions']} functions -> {output_path}")
    return data
