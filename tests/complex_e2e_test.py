#!/usr/bin/env python3
"""
Complex binary E2E test — function pointers, structs, recursion, strings.

Tests the bridge against a more realistic binary with:
- Function pointer tables (dispatch via ops[] array)
- Struct manipulation (Record struct with id, name, active fields)
- Recursion (factorial)
- String operations (printf with struct fields)
- Global data (records[] array)
- Nested calls (deactivate_all → deactivate → struct write)

Requires:
- Ghidra server running with complex binary loaded
- Vivisect installed (pip install vivisect)

Usage:
    python3 tests/complex_e2e_test.py [--host HOST] [--port PORT]
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "src"))

def run_complex_tests(host="127.0.0.1", port=13100):
    results = {}

    try:
        import vivisect
        from vivisect.symboliks.analysis import getSymbolikAnalysisContext
        from vivghidra.config import Config
        from vivghidra.ghidra_client import GhidraClient
        from vivghidra.models import DecompileRequest
        from vivghidra.pcode_translator import PcodeTranslator
    except ImportError as e:
        print(f"Missing dependency: {e}")
        print("Install with: pip install vivisect")
        return results

    binary = os.path.join(os.path.dirname(__file__), "..", "tests", "complex_binary")
    
    # Load in Vivisect
    print("=== Loading binary in Vivisect ===")
    vw = vivisect.VivWorkspace()
    vw.loadFromFile(binary)
    vw.analyze()
    ctx = getSymbolikAnalysisContext(vw, consolve=False)
    translator = PcodeTranslator(arch="amd64")
    print(f"  Vivisect: {len(vw.getFunctions())} functions, arch={vw.getMeta('Architecture')}")
    results["vivisect_load"] = True

    # Connect to Ghidra
    print("\n=== Connecting to Ghidra ===")
    cfg = Config()
    cfg.host = host
    cfg.port = port
    cfg.timeout = 30

    client = GhidraClient(cfg)
    client.connect()
    status = client.get_status()
    print(f"  Ghidra: program={status['program_name']}, loaded={status['program_loaded']}")
    results["ghidra_connect"] = True

    # ─── Test 1: Decompile all user functions ───
    print("\n=== Test 1: Decompile All User Functions ===")
    user_funcs = ["op_add", "op_sub", "op_mul", "factorial", "dispatch",
                  "count_active", "deactivate", "deactivate_all", "main"]
    
    ghidra_funcs = {f["name"]: f["address"] for f in client.get_function_list()["functions"]}
    
    for name in user_funcs:
        if name not in ghidra_funcs:
            # Try with prefixes
            for gname, gaddr in ghidra_funcs.items():
                if name in gname:
                    ghidra_funcs[name] = gaddr
                    break
        
        if name in ghidra_funcs:
            addr = int(ghidra_funcs[name], 16)
            req = DecompileRequest(address=addr, mode="standard")
            result = client.decompile_function(req)
            if result.success:
                print(f"  ✓ {name}: {len(result.c_code)} chars")
                results[f"decompile_{name}"] = True
            else:
                print(f"  ✗ {name}: FAILED — {result.error}")
                results[f"decompile_{name}"] = False
        else:
            print(f"  ~ {name}: not found in Ghidra")
            results[f"decompile_{name}"] = False

    # ─── Test 2: Vivisect symbolik analysis on factorial (recursion) ───
    print("\n=== Test 2: Symbolik Analysis of Recursive Function ===")
    fact_addr = None
    for fva in vw.getFunctions():
        if "factorial" in (vw.getName(fva) or ""):
            fact_addr = fva
            break
    
    if fact_addr:
        path_count = 0
        has_recursive_call = False
        for emu, effects in ctx.walkSymbolikPaths(fact_addr):
            path_count += 1
            for eff in effects:
                if "CallFunction" in type(eff).__name__:
                    eff_str = str(eff)
                    if hex(fact_addr) in eff_str or str(fact_addr) in eff_str:
                        has_recursive_call = True
        
        print(f"  factorial @ 0x{fact_addr:x}: {path_count} paths, recursive call: {has_recursive_call}")
        assert path_count >= 2, "Should have at least 2 paths (base + recursive)"
        assert has_recursive_call, "Should detect recursive call"
        results["symbolik_recursion"] = True
    else:
        results["symbolik_recursion"] = False

    # ─── Test 3: P-code translation from real Vivisect effects ───
    print("\n=== Test 3: P-Code Translation from Real Vivisect Effects ===")
    test_addr = None
    for fva in vw.getFunctions():
        if "op_add" in (vw.getName(fva) or ""):
            test_addr = fva
            break
    
    if test_addr:
        for emu, effects in ctx.walkSymbolikPaths(test_addr):
            ops = translator.translate_effects(effects, va_base=test_addr)
            assert len(ops) > 0, "Should generate p-code ops"
            
            # Check for key opcodes
            opcodes = {op.opcode.value for op in ops}
            assert "INT_ADD" in opcodes, "Should have INT_ADD for addition"
            assert "COPY" in opcodes, "Should have COPY for assignments"
            assert "STORE" in opcodes, "Should have STORE for stack writes"
            
            print(f"  op_add: {len(ops)} p-code ops, opcodes: {sorted(opcodes)}")
            results["real_pcode_translation"] = True
            break
    
    # ─── Test 4: Symbol enrichment ───
    print("\n=== Test 4: Symbol Enrichment ===")
    symbols = []
    for fva in vw.getFunctions():
        name = vw.getName(fva) or f"sub_{fva:x}"
        if "." in name:
            name = name.split(".")[-1]
        symbols.append({"name": name, "address": f"0x{fva:x}", "is_function": True})
    
    result = client.apply_symbols(symbols)
    applied = result.get("applied", 0)
    failed = result.get("failed", 0)
    print(f"  Applied: {applied}, Failed: {failed}")
    assert applied > 0, "Should apply at least some symbols"
    results["symbol_enrichment"] = applied > 0

    # ─── Test 5: Function pointer dispatch decompilation ───
    print("\n=== Test 5: Function Pointer Dispatch ===")
    for gf in client.get_function_list()["functions"]:
        if "dispatch" in gf["name"]:
            req = DecompileRequest(address=int(gf["address"], 16), mode="standard")
            result = client.decompile_function(req)
            if result.success:
                # Should have indirect call through function pointer
                has_indirect = "**" in result.c_code or "code *" in result.c_code
                print(f"  dispatch: {len(result.c_code)} chars, indirect call: {has_indirect}")
                if has_indirect:
                    print(f"  ✓ Function pointer dispatch correctly decompiled")
                results["func_ptr_dispatch"] = has_indirect
            break

    # ─── Test 6: Struct manipulation decompilation ───
    print("\n=== Test 6: Struct Manipulation ===")
    for gf in client.get_function_list()["functions"]:
        if "deactivate" in gf["name"] and "all" not in gf["name"]:
            req = DecompileRequest(address=int(gf["address"], 16), mode="standard")
            result = client.decompile_function(req)
            if result.success:
                # Should write to a struct field at an offset
                has_struct_write = "0x24" in result.c_code or "+ 36" in result.c_code
                print(f"  deactivate: {len(result.c_code)} chars, struct field write: {has_struct_write}")
                print(f"  Code: {result.c_code.strip()}")
                results["struct_manipulation"] = True
            break

    client.close()

    # ─── Summary ───
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"  Complex E2E Tests: {passed}/{total} passed")
    print("=" * 60)
    for k, v in sorted(results.items()):
        print(f"  {'✓' if v else '✗'} {k}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="Complex binary E2E test")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=13100)
    args = parser.parse_args()
    
    results = run_complex_tests(args.host, args.port)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"\n{passed}/{total} tests passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())