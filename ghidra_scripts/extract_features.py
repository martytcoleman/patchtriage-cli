# Ghidra headless script: extract per-function features to JSON.
# Usage: analyzeHeadless <project_dir> <project_name> -import <binary> \
#        -postScript extract_features.py <output.json>
#
# Runs inside Ghidra's Jython environment. Do NOT run with standard Python.
# @category PatchTriage

import json
import sys
import os
from collections import Counter

from ghidra.program.model.block import BasicBlockModel
from ghidra.util.task import ConsoleTaskMonitor

args = getScriptArgs()
if len(args) < 1:
    print("ERROR: pass output path as script argument")
    sys.exit(1)

output_path = args[0]
monitor = ConsoleTaskMonitor()
listing = currentProgram.getListing()
func_mgr = currentProgram.getFunctionManager()
mem = currentProgram.getMemory()
bbm = BasicBlockModel(currentProgram)

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
                if hasattr(obj, 'longValue'):
                    v = obj.longValue()
                    if 2 <= abs(v) <= 0xFFFFFFFF:
                        constants.add(v)

    # --- basic-block count ---
    block_count = 0
    block_iter = bbm.getCodeBlocksContaining(body, monitor)
    while block_iter.hasNext():
        block_iter.next()
        block_count += 1

    # --- referenced strings ---
    strings = []
    ref_mgr = currentProgram.getReferenceManager()
    ref_iter = ref_mgr.getReferenceIterator(body.getMinAddress())
    while ref_iter.hasNext():
        ref = ref_iter.next()
        if not body.contains(ref.getFromAddress()):
            continue
        to_addr = ref.getToAddress()
        data = listing.getDataAt(to_addr)
        if data is not None and data.hasStringValue():
            s = data.getValue()
            if s and len(s) >= 2:
                strings.append(str(s))

    # --- called functions (imports + internal) ---
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
        "size": body.getNumAddresses(),
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

result = {
    "binary": currentProgram.getExecutablePath(),
    "arch": currentProgram.getLanguage().getProcessor().toString(),
    "num_functions": len(functions_out),
    "functions": functions_out,
}

with open(output_path, "w") as f:
    json.dump(result, f, indent=2, default=str)

print("Extracted %d functions -> %s" % (len(functions_out), output_path))
