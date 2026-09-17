#!/usr/bin/env python3
"""
Real-world binary testing: /usr/bin/base64 (stripped, x86-64, 39KB)

Tests the full Vivisect-Ghidra bridge pipeline against a real stripped binary:
1. Connect to Ghidra server
2. Get function list
3. Decompile functions
4. Run Vivisect symbolik analysis
5. Test symbol enrichment
6. Test UI features (set_comment, rename_symbol, set_signature)
7. Verify C output quality
"""

import sys
import os
import json
import time

# Add the Python source to path
sys.path.insert(0, "/tmp/viv-ghidra-decompiler-fork/python/src")

from vivghidra.config import Config
from vivghidra.ghidra_client import GhidraClient, GhidraConnectionError
from vivghidra.models import DecompileRequest, DecompileResult, SymbolInfo

PASS = 0
FAIL = 0
RESULTS = []

def test(name, condition, detail=""):
    global PASS, FAIL
    if condition:
        PASS += 1
        RESULTS.append(f"  ✓ {name}")
    else:
        FAIL += 1
        RESULTS.append(f"  ✗ {name} — {detail}")

def section(title):
    RESULTS.append(f"\n[{title}]")

# ─── 1. Connect to Ghidra ───
section("Connection")
cfg = Config()
cfg.host = "localhost"
cfg.port = 13100
cfg.timeout = 60

client = GhidraClient(cfg)
try:
    client.connect()
    test("Connected to Ghidra server", client.connected)
except Exception as e:
    test("Connected to Ghidra server", False, str(e))
    print("\n".join(RESULTS))
    print(f"\n{PASS} passed, {FAIL} failed")
    sys.exit(1)

ping = client.ping()
test("Ping response", ping.get("pong") is True, str(ping))

status = client.get_status()
test("Program loaded", status.get("program_loaded") is True, str(status))
test("Program name is base64", "base64" in status.get("program_name", "").lower(), status.get("program_name", ""))

# ─── 2. Get function list ───
section("Function Discovery")
func_list = client.get_function_list()
functions = func_list.get("functions", [])
test("Got function list", len(functions) > 0, "empty list")
test("Has multiple functions", len(functions) > 5, f"only {len(functions)} functions")
test("Has reasonable function count (<500)", len(functions) < 500, f"{len(functions)} functions")

# Print some function names
RESULTS.append(f"  Total functions: {len(functions)}")
# Show first 10
for f in functions[:10]:
    RESULTS.append(f"    {f.get('address', '?')} {f.get('name', '?')} ({f.get('size', '?')} bytes)")

# Find user functions (non-library, by looking for non-FUN_ names or small addresses)
user_funcs = [f for f in functions if not f.get("name", "").startswith("FUN_") and not f.get("name", "").startswith("_")]
entry_funcs = [f for f in functions if "entry" in f.get("name", "").lower()]
test("Found entry point", len(entry_funcs) > 0, "no entry function")
test("Found non-auto-named functions", len(user_funcs) > 0, "all functions are FUN_*")

# ─── 3. Decompile functions ───
section("Decompilation")
# Try decompiling a few functions
decompiled = []
test_addrs = []
for f in functions[:5]:  # Try first 5
    addr = f.get("address", "")
    name = f.get("name", "")
    if not addr:
        continue
    try:
        # Handle various address formats: "0x401000", "001023a0", "401000"
        if addr.startswith("0x") or addr.startswith("0X"):
            addr_int = int(addr, 16)
        else:
            addr_int = int(addr, 16)  # always treat as hex
        req = DecompileRequest(address=addr_int, mode="standard")
        result = client.decompile_function(req)
        if result.success and result.c_code:
            decompiled.append((addr, name, result))
            test_addrs.append(addr)
            test(f"Decompiled {name} at {addr}", True)
            test(f"  C code length > 50", len(result.c_code) > 50, f"only {len(result.c_code)} chars")
            test(f"  Contains function braces", "{" in result.c_code and "}" in result.c_code)
        else:
            test(f"Decompiled {name} at {addr}", False, result.error or "no c_code")
    except Exception as e:
        test(f"Decompiled {name} at {addr}", False, str(e))

test("At least 3 functions decompiled", len(decompiled) >= 3, f"only {len(decompiled)}")

# Show a sample decompilation
if decompiled:
    addr, name, result = decompiled[0]
    RESULTS.append(f"\n  Sample decompilation of {name} at {addr}:")
    for line in result.c_code.split("\n")[:15]:
        RESULTS.append(f"    {line}")
    if len(result.c_code.split("\n")) > 15:
        RESULTS.append(f"    ... ({len(result.c_code.split(chr(10)))} lines total)")

# ─── 4. Symbol enrichment ───
section("Symbol Enrichment")
# Apply some symbols and test if decompilation improves
if test_addrs:
    # Try renaming a function
    test_addr = test_addrs[0]
    try:
        result = client.rename_symbol(test_addr, "test_renamed_func", is_function=True)
        test("Rename function via RPC", result.get("success") is True, str(result))
    except Exception as e:
        test("Rename function via RPC", False, str(e))

    # Re-decompile to see if name changed
    try:
        addr_int = int(test_addr, 16) if not test_addr.startswith("0x") else int(test_addr, 16)
        # Handle both "0x..." and "0010..." formats
        if not test_addr.startswith("0x"):
            addr_int = int(test_addr, 16)
        req = DecompileRequest(address=addr_int, mode="standard")
        result = client.decompile_function(req)
        if result.success:
            test("Name appears in re-decompiled output", "test_renamed_func" in result.c_code,
                 f"name not found in output: {result.c_code[:100]}")
    except Exception as e:
        test("Re-decompile after rename", False, str(e))

# ─── 5. Set comment ───
section("Comment Feature")
if test_addrs:
    test_addr = test_addrs[0]
    try:
        result = client.set_comment(test_addr, "This is a test comment from real-world testing")
        test("Set comment via RPC", result.get("success") is True, str(result))
    except Exception as e:
        test("Set comment via RPC", False, str(e))

# ─── 6. Set signature ───
section("Signature Feature")
if test_addrs:
    test_addr = test_addrs[1] if len(test_addrs) > 1 else test_addrs[0]
    try:
        result = client.set_signature(test_addr, "sig_test_func", "int", ["int", "int"], "cdecl")
        test("Set signature via RPC", result.get("success") is True, str(result))
    except Exception as e:
        test("Set signature via RPC", False, str(e))

# ─── 7. Vivisect symbolik analysis ───
section("Vivisect Symbolik Analysis")
try:
    import vivisect
    vw = vivisect.VivWorkspace()
    vw.loadFromFile("/tmp/vivghidra_realworld_base64")
    vw.analyze()

    # Check Vivisect found functions
    viv_funcs = list(vw.getFunctions())
    test("Vivisect loaded binary", len(viv_funcs) > 0, "no functions found")
    test("Vivisect found multiple functions", len(viv_funcs) > 5, f"only {len(viv_funcs)}")
    RESULTS.append(f"  Vivisect found {len(viv_funcs)} functions")

    # Try symbolik analysis on a small function
    from vivisect.symboliks.analysis import getSymbolikAnalysisContext
    ctx = getSymbolikAnalysisContext(vw, consolve=False)
    test("Symbolik context created", ctx is not None, "None")

    if ctx:
        # Find a small function to test
        small_funcs = sorted(viv_funcs, key=lambda fva: len(vw.getFunctionBlocks(fva)) if hasattr(vw, 'getFunctionBlocks') else 1)
        test_symbolik = False
        for fva in small_funcs[:5]:
            try:
                graph = ctx.getSymbolikGraph(fva)
                if graph is not None:
                    test_symbolik = True
                    RESULTS.append(f"  Symbolik graph for 0x{fva:x}: {graph.getGraphSize() if hasattr(graph, 'getGraphSize') else 'unknown'} nodes")
                    break
            except Exception as e:
                RESULTS.append(f"  Symbolik analysis failed for 0x{fva:x}: {e}")
                continue

        test("Symbolik analysis succeeded on at least one function", test_symbolik)

    # Test p-code translation and address mapping
    from vivghidra.pcode_translator import PcodeTranslator
    from vivghidra.symbol_extractor import SymbolExtractor

    translator = PcodeTranslator(arch="amd64")
    extractor = SymbolExtractor(vw)

    # Compute address mapping between Vivisect and Ghidra
    viv_funcs_map = {}
    for vfva in viv_funcs:
        vname = vw.getName(vfva) or ""
        # Strip Vivisect's filename prefix and plt_ prefix
        if "." in vname:
            vname = vname.split(".")[-1]
        # Also try without plt_ prefix (Vivisect adds plt_ to PLT stubs)
        if vname.startswith("plt_"):
            vname = vname[4:]
        viv_funcs_map[vname] = vfva

    addr_offset = 0
    for gf in functions:
        gname = gf.get("name", "")
        if gname in viv_funcs_map:
            g_addr = int(gf.get("address", "0"), 16)
            v_addr = viv_funcs_map[gname]
            addr_offset = g_addr - v_addr
            RESULTS.append(f"  Address mapping: offset = {addr_offset:#x} (matched on '{gname}')")
            RESULTS.append(f"    Ghidra 0x{g_addr:x} ↔ Vivisect 0x{v_addr:x}")
            break

    test("Address mapping computed", addr_offset != 0, "no matching function names found")

    # Extract symbols and map addresses
    if viv_funcs:
        symbols = extractor.extract_for_function(viv_funcs[0])
        test("Symbol extraction from real binary", len(symbols) > 0, "no symbols extracted")
        RESULTS.append(f"  Extracted {len(symbols)} symbols for first function")

        # Map addresses to Ghidra's space
        for s in symbols:
            s.address = s.address + addr_offset
            RESULTS.append(f"    {s.name} → Ghidra 0x{s.address:x} (func={s.is_function})")

        # Send mapped symbols to Ghidra
        try:
            sym_dicts = [s.to_dict() for s in symbols]
            apply_result = client.apply_symbols(sym_dicts)
            applied = apply_result.get("applied", 0)
            test("Applied symbols to Ghidra (with address mapping)", applied > 0, str(apply_result))
        except Exception as e:
            test("Applied symbols to Ghidra (with address mapping)", False, str(e))

except ImportError:
    test("Vivisect available", False, "vivisect not installed")
except Exception as e:
    test("Vivisect analysis", False, str(e))

# ─── Summary ───
section("Summary")
RESULTS.append(f"  Total: {PASS} passed, {FAIL} failed")
RESULTS.append(f"  Binary: /usr/bin/base64 (stripped, x86-64, 39KB)")
RESULTS.append(f"  Functions discovered: {len(functions)}")

print("\n".join(RESULTS))
print(f"\n{'='*60}")
if FAIL == 0:
    print(f"  ALL TESTS PASSED ({PASS} tests)")
else:
    print(f"  {PASS} passed, {FAIL} failed")
print(f"{'='*60}")

client.close()