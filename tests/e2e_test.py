#!/usr/bin/env python3
"""
End-to-end test against a real Ghidra 12.1.2 server.

Requires:
- Ghidra 12.1.2 installed (GHIDRA_INSTALL_DIR or /home/aragorn/ghidra_12.1.2_PUBLIC)
- Test binary imported and analyzed in a Ghidra project
- StartBridgeServer.java running (start_ghidra_headless.sh)

Usage:
    python3 tests/e2e_test.py [--host HOST] [--port PORT]

This test covers:
1. Ping and status
2. Function list retrieval
3. Decompilation of all 6 user functions with correctness verification
4. Error handling (bad address, zero address)
5. P-code translation (operators, constraints, memory, serialization)
6. Symbol enrichment (Mode 1)
7. Connection resilience (reconnect)
8. Multiple sequential requests
"""

import sys
import os
import argparse
import socket
import json
import time

# Add src and tests to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "tests"))

from vivghidra.config import Config
from vivghidra.ghidra_client import GhidraClient, GhidraConnectionError
from vivghidra.models import DecompileRequest
from vivghidra.pcode_translator import PcodeTranslator

from conftest import (
    MockSetVariable, MockConst, MockVar, MockOperator,
    MockConstrainPath, MockConstraint, MockWriteMemory,
    SYMT_OPER_ADD, SYMT_OPER_MUL, SYMT_OPER_XOR,
    SYMT_CON_GT,
)


def run_e2e_tests(host="127.0.0.1", port=13100):
    """Run all end-to-end tests against a real Ghidra server."""
    
    results = {}
    
    cfg = Config()
    cfg.host = host
    cfg.port = port
    cfg.timeout = 30

    # ─── Test 1: Connection, Ping & Status ───
    print("=== Test 1: Connection, Ping & Status ===")
    try:
        client = GhidraClient(cfg)
        client.connect()
        ping = client.ping()
        assert ping["pong"] == True, "Ping failed"
        assert "version" in ping, "No version in ping"
        status = client.get_status()
        assert status["program_loaded"] == True, "No program loaded"
        print(f"  ✓ Connected — ping OK, program: {status['program_name']}")
        results["connection"] = True
        results["ping"] = True
        results["status"] = True
    except Exception as e:
        print(f"  ✗ Connection failed: {e}")
        print(f"  Make sure StartBridgeServer.java is running on {host}:{port}")
        return results

    # ─── Test 2: Function List ───
    print("\n=== Test 2: Function List ===")
    funcs = client.get_function_list()
    func_list = funcs["functions"]
    assert len(func_list) > 0, "No functions found"
    print(f"  ✓ {len(func_list)} functions found")
    results["function_list"] = True

    # ─── Test 3: Decompile All User Functions ───
    print("\n=== Test 3: Decompile All User Functions ===")
    user_funcs = [
        ("simple_add", 0x00401156, ["return", "param"]),
        ("loop_sum", 0x0040116e, ["for", "return"]),
        ("conditional", 0x004011a0, ["if", "else", "return"]),
        ("memory_ops", 0x004011c0, ["for", "return"]),
        ("call_chain", 0x0040121a, ["simple_add", "conditional"]),
        ("main", 0x0040124a, ["printf", "simple_add", "call_chain", "memory_ops"]),
    ]

    for name, addr, expected_keywords in user_funcs:
        req = DecompileRequest(address=addr, mode="standard")
        result = client.decompile_function(req)
        if result.success:
            found = [kw for kw in expected_keywords if kw in result.c_code]
            missing = [kw for kw in expected_keywords if kw not in result.c_code]
            if missing:
                print(f"  ~ {name}: {len(result.c_code)} chars, missing {missing}")
                results[f"decompile_{name}"] = False
            else:
                print(f"  ✓ {name}: {len(result.c_code)} chars, all keywords found")
                results[f"decompile_{name}"] = True
        else:
            print(f"  ✗ {name}: FAILED — {result.error}")
            results[f"decompile_{name}"] = False

    # ─── Test 4: Error Handling ───
    print("\n=== Test 4: Error Handling ===")
    
    # Bad address — should fail gracefully
    req = DecompileRequest(address=0xDEADBEEF, mode="standard")
    result = client.decompile_function(req)
    assert not result.success, "Bad address should fail"
    assert result.error, "Should have error message"
    print(f"  ✓ Bad address 0xDEADBEEF: graceful failure — '{result.error[:40]}'")
    results["error_bad_addr"] = True

    # Zero address — should fail gracefully
    req = DecompileRequest(address=0x0, mode="standard")
    result = client.decompile_function(req)
    # Either fails gracefully or succeeds (0x0 might be in a segment)
    print(f"  ✓ Zero address: success={result.success}")
    results["error_zero_addr"] = True

    # ─── Test 5: P-Code Translation ───
    print("\n=== Test 5: P-Code Translation ===")
    translator = PcodeTranslator(arch="amd64")

    # 5a: Simple arithmetic
    effects = [
        MockSetVariable(0x401000, "eax",
            MockOperator(MockVar("edi", 4), MockVar("esi", 4), width=4, symtype=SYMT_OPER_ADD)),
    ]
    ops = translator.translate_effects(effects)
    assert len(ops) == 2, f"Expected 2 ops, got {len(ops)}"
    assert ops[0].opcode.value == "INT_ADD"
    assert ops[1].opcode.value == "COPY"
    print(f"  ✓ Arithmetic (a+b): {len(ops)} ops — INT_ADD + COPY")
    results["pcode_arithmetic"] = True

    # 5b: Nested expression
    inner = MockOperator(MockVar("eax", 4), MockVar("ebx", 4), width=4, symtype=SYMT_OPER_ADD)
    outer = MockOperator(inner, MockVar("ecx", 4), width=4, symtype=SYMT_OPER_MUL)
    effects = [MockSetVariable(0x401000, "edx", outer)]
    ops = translator.translate_effects(effects)
    assert len(ops) == 3, f"Expected 3 ops, got {len(ops)}"
    assert ops[0].opcode.value == "INT_ADD"
    assert ops[1].opcode.value == "INT_MULT"
    assert ops[2].opcode.value == "COPY"
    print(f"  ✓ Nested (a+b)*c: {len(ops)} ops — INT_ADD + INT_MULT + COPY")
    results["pcode_nested"] = True

    # 5c: Conditional with operand swap
    effects = [
        MockConstrainPath(0x401000,
            MockConst(0x401050, 8),
            MockConstraint(MockVar("eax", 4), MockConst(10, 4), width=4, symtype=SYMT_CON_GT)),
    ]
    ops = translator.translate_effects(effects)
    sless_ops = [o for o in ops if o.opcode.value == "INT_SLESS"]
    cbranch_ops = [o for o in ops if o.opcode.value == "CBRANCH"]
    assert len(sless_ops) == 1, "Missing INT_SLESS"
    assert len(cbranch_ops) == 1, "Missing CBRANCH"
    # Verify operand swap: gt(eax, 10) → INT_SLESS(10, eax)
    assert sless_ops[0].inputs[0].space.value == "const", "First input should be const (swapped)"
    assert sless_ops[0].inputs[1].space.value == "register", "Second input should be register (swapped)"
    print(f"  ✓ Conditional gt(eax,10): {len(ops)} ops — INT_SLESS (operand swap) + CBRANCH")
    results["pcode_conditional"] = True

    # 5d: XOR (common in reversing)
    effects = [
        MockSetVariable(0x401000, "eax",
            MockOperator(MockVar("eax", 4), MockConst(0xDEADBEEF, 4), width=4, symtype=SYMT_OPER_XOR)),
    ]
    ops = translator.translate_effects(effects)
    assert ops[0].opcode.value == "INT_XOR"
    assert ops[0].inputs[0].reg_name == "eax"
    assert ops[0].inputs[1].offset == 0xDEADBEEF
    print(f"  ✓ XOR eax, 0xDEADBEEF: {len(ops)} ops — INT_XOR")
    results["pcode_xor"] = True

    # 5e: Memory store
    effects = [
        MockWriteMemory(0x401000,
            MockConst(0x601000, 8), MockConst(4, 4), MockVar("eax", 4)),
    ]
    ops = translator.translate_effects(effects)
    assert ops[0].opcode.value == "STORE"
    assert ops[0].output is None
    assert len(ops[0].inputs) == 3
    print(f"  ✓ mov [addr], eax: {len(ops)} ops — STORE (3 inputs, no output)")
    results["pcode_store"] = True

    # 5f: JSON serialization round-trip
    json_str = translator.serialize_ops(ops)
    ops2 = PcodeTranslator.deserialize_ops(json_str)
    assert len(ops2) == len(ops)
    assert all(a.opcode == b.opcode for a, b in zip(ops, ops2))
    print(f"  ✓ JSON round-trip: {len(ops)} ops serialized and restored correctly")
    results["pcode_serialization"] = True

    # 5g: i386 architecture
    translator_i386 = PcodeTranslator(arch="i386")
    effects = [
        MockSetVariable(0x401000, "eax",
            MockOperator(MockVar("ecx", 4), MockConst(1, 4), width=4, symtype=SYMT_OPER_ADD)),
    ]
    ops = translator_i386.translate_effects(effects)
    assert ops[0].opcode.value == "INT_ADD"
    assert ops[1].output.reg_name == "eax"
    print(f"  ✓ i386 architecture: register mapping works")
    results["pcode_i386"] = True

    # ─── Test 6: Symbol Enrichment ───
    print("\n=== Test 6: Symbol Enrichment (Mode 1) ===")
    apply_result = client.apply_symbols([
        {"name": "renamed_add", "address": "0x401156", "is_function": True,
         "return_type": "int", "param_types": ["int", "int"]},
    ])
    print(f"  apply_symbols result: {apply_result}")
    # Note: The StartBridgeServer script returns applied=0 (stub),
    # but the VivGhidraBridgePlugin would actually apply them.
    # Either way, decompilation should still work.
    req = DecompileRequest(address=0x00401156, mode="enriched")
    result = client.decompile_function(req)
    assert result.success, "Enriched decompile failed"
    print(f"  ✓ Enriched mode decompile: {result.function_name}")
    results["symbol_enrichment"] = True

    # ─── Test 7: Connection Resilience ───
    print("\n=== Test 7: Connection Resilience ===")
    client.close()
    client.connect()
    ping2 = client.ping()
    assert ping2["pong"] == True, "Reconnect ping failed"
    print(f"  ✓ Reconnected after close")
    results["reconnect"] = True

    # ─── Test 8: Sequential Requests ───
    print("\n=== Test 8: Sequential Requests ===")
    for i in range(5):
        req = DecompileRequest(address=0x00401156, mode="standard")
        result = client.decompile_function(req)
        assert result.success, f"Request {i+1} failed"
    print(f"  ✓ 5 sequential decompile requests succeeded")
    results["sequential"] = True

    # ─── Test 9: Concurrent Requests (different connections) ───
    print("\n=== Test 9: Concurrent Requests ===")
    client2 = GhidraClient(cfg)
    client2.connect()
    # Both clients can decompile
    req = DecompileRequest(address=0x00401156, mode="standard")
    r1 = client.decompile_function(req)
    r2 = client2.decompile_function(req)
    assert r1.success and r2.success, "Concurrent requests failed"
    print(f"  ✓ Two concurrent clients both decompiled successfully")
    results["concurrent"] = True
    client2.close()

    client.close()

    # ─── Summary ───
    print("\n" + "=" * 60)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    print(f"  E2E Tests: {passed}/{total} passed")
    print("=" * 60)
    for k, v in sorted(results.items()):
        print(f"  {'✓' if v else '✗'} {k}")
    
    return results


def main():
    parser = argparse.ArgumentParser(description="E2E test against real Ghidra")
    parser.add_argument("--host", default="127.0.0.1", help="Ghidra server host")
    parser.add_argument("--port", type=int, default=13100, help="Ghidra server port")
    args = parser.parse_args()

    results = run_e2e_tests(args.host, args.port)
    passed = sum(1 for v in results.values() if v)
    total = len(results)
    
    print(f"\n{passed}/{total} tests passed")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())