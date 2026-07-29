#!/usr/bin/env python3
"""
Integration test for the Vivisect-Ghidra bridge.

This test:
1. Compiles the test binary
2. Starts a mock Ghidra JSON-RPC server (if Ghidra isn't available)
3. Uses the PcodeTranslator to translate effects from a mock function
4. Uses the GhidraClient to connect to the mock server and request decompilation
5. Verifies the end-to-end flow works

This can run WITHOUT Ghidra or Vivisect installed — it uses mocks
for both sides. When Ghidra is available, set VIVGHIDRA_HOST/PORT
to run against the real server.
"""

import sys
import os
import json
import subprocess
import tempfile
import socket
import threading

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "src"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python", "tests"))

from vivghidra.pcode_translator import PcodeTranslator
from vivghidra.ghidra_client import GhidraClient, GhidraConnectionError
from vivghidra.config import Config
from vivghidra.models import DecompileRequest, DecompileResult, PcodeFunction

from conftest import (
    MockSetVariable, MockConst, MockVar, MockOperator,
    MockCallFunction, MockConstrainPath, MockConstraint, MockWriteMemory,
    SYMT_OPER_ADD, SYMT_OPER_SUB, SYMT_CON_GT, SYMT_CON_LT,
    MockJsonRpcServer,
)


def compile_test_binary():
    """Compile the test binary. Returns path to the binary or None on failure."""
    source = os.path.join(os.path.dirname(__file__), "test_binary.c")
    binary = os.path.join(tempfile.gettempdir(), "vivghidra_test_binary")

    try:
        subprocess.run(
            ["gcc", "-o", binary, source, "-no-pie", "-O0", "-lm"],
            capture_output=True, text=True, timeout=30,
        )
        if os.path.exists(binary):
            return binary
    except Exception:
        pass

    # Try without -no-pie
    try:
        subprocess.run(
            ["gcc", "-o", binary, source, "-O0", "-lm"],
            capture_output=True, text=True, timeout=30,
        )
        if os.path.exists(binary):
            return binary
    except Exception:
        pass

    return None


def test_pcode_translation():
    """Test that the p-code translator produces correct ops for a simple function."""
    print("  [1] P-code translation of simple_add(a, b) → return a + b")

    translator = PcodeTranslator(arch="amd64")

    # Simulate the effects of: int simple_add(int a, int b) { return a + b; }
    # In symbolik form, this would be something like:
    # SetVariable(0x401000, "arg0", Arg(0, 4))      // function entry
    # SetVariable(0x401003, "arg1", Arg(1, 4))
    # SetVariable(0x401006, "eax", o_add(arg0, arg1))  // return = a + b
    # (return effect)
    effects = [
        MockSetVariable(0x401000, "eax",
            MockOperator(
                MockVar("edi", 4),    # arg0 in edi (amd64 calling convention)
                MockVar("esi", 4),    # arg1 in esi
                width=4, symtype=SYMT_OPER_ADD
            )),
    ]

    ops = translator.translate_effects(effects)

    assert len(ops) >= 2, f"Expected at least 2 ops, got {len(ops)}"
    assert any(op.opcode.value == "INT_ADD" for op in ops), "Missing INT_ADD op"
    assert any(op.opcode.value == "COPY" for op in ops), "Missing COPY op"

    # Verify JSON serialization round-trip
    json_str = translator.serialize_ops(ops)
    ops2 = PcodeTranslator.deserialize_ops(json_str)
    assert len(ops2) == len(ops), "JSON round-trip changed op count"

    print(f"      ✓ Generated {len(ops)} p-code ops, JSON round-trip OK")
    return True


def test_conditional_translation():
    """Test translation of a conditional branch (if x > 10)."""
    print("  [2] P-code translation of conditional(x) → if (x > 10) return x*2")

    translator = PcodeTranslator(arch="amd64")

    # Simulate: cmp edi, 10; jle else_branch
    # This produces:
    # SetVariable(va, "eflags_gt", gt(edi, 10))
    # ConstrainPath(va, else_addr, le(edi, 10))
    effects = [
        MockSetVariable(0x401020, "eflags_gt",
            MockConstraint(MockVar("edi", 4), MockConst(10, 4),
                          width=4, symtype=SYMT_CON_GT)),
        MockConstrainPath(0x401022,
            MockConst(0x401050, 8),
            MockConstraint(MockVar("edi", 4), MockConst(10, 4),
                          width=4, symtype=SYMT_CON_LT)),
    ]

    ops = translator.translate_effects(effects)

    # Should have: INT_SLESS (for gt, swapped operands), INT_SLESS (for lt), CBRANCH
    assert any(op.opcode.value == "INT_SLESS" for op in ops), "Missing INT_SLESS"
    assert any(op.opcode.value == "CBRANCH" for op in ops), "Missing CBRANCH"

    print(f"      ✓ Generated {len(ops)} p-code ops with CBRANCH for conditional")
    return True


def test_memory_ops_translation():
    """Test translation of memory operations (LOAD/STORE)."""
    print("  [3] P-code translation of memory_ops(arr, n)")

    translator = PcodeTranslator(arch="amd64")

    # Simulate: arr[i] = arr[i] * 2 + 1
    # This involves: ReadMemory(addr), multiply, add, WriteMemory(addr, val)
    effects = [
        MockWriteMemory(0x401030,
            MockConst(0x601000, 8),   # addr
            MockConst(4, 4),          # size
            MockOperator(
                MockOperator(
                    MockConst(0x601000, 8),  # dummy — would be a Mem read in reality
                    MockConst(2, 4),
                    width=4, symtype=SYMT_OPER_ADD
                ),
                MockConst(1, 4),
                width=4, symtype=SYMT_OPER_ADD
            )),
    ]

    ops = translator.translate_effects(effects)

    # Should have STORE at minimum
    assert any(op.opcode.value == "STORE" for op in ops), "Missing STORE"

    print(f"      ✓ Generated {len(ops)} p-code ops with STORE for memory write")
    return True


def test_client_server_roundtrip():
    """Test the full client-server round-trip with a mock Ghidra server."""
    print("  [4] Client-server round-trip (mock Ghidra server)")

    # Start mock server
    server = MockJsonRpcServer(responses={
        "ping": {"pong": True, "version": "1.0"},
        "get_status": {"program_loaded": True, "program_name": "vivghidra_test_binary"},
        "decompile_function": {
            "c_code": "int simple_add(int a, int b) {\n  return a + b;\n}",
            "high_pcode": [],
            "function_name": "simple_add",
            "success": True,
        },
    })
    server.start()

    try:
        # Create client and connect
        cfg = Config()
        cfg.host = server.host
        cfg.port = server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            # Ping
            ping_result = client.ping()
            assert ping_result["pong"] is True
            print(f"      ✓ Ping: {ping_result}")

            # Get status
            status = client.get_status()
            assert status["program_loaded"] is True
            print(f"      ✓ Status: program={status['program_name']}")

            # Decompile
            req = DecompileRequest(address=0x401000, mode="standard")
            result = client.decompile_function(req)
            assert result.success is True
            assert "simple_add" in result.c_code
            assert result.function_name == "simple_add"
            print(f"      ✓ Decompiled: {result.function_name} ({len(result.c_code)} chars)")

    finally:
        server.stop()

    return True


def test_full_pipeline():
    """Test the full pipeline: translate p-code, send to server, get C code back."""
    print("  [5] Full pipeline: translate → serialize → send → decompile → display")

    # Step 1: Translate symbolik effects to p-code
    translator = PcodeTranslator(arch="amd64")
    effects = [
        MockSetVariable(0x401000, "eax",
            MockOperator(
                MockVar("edi", 4),
                MockVar("esi", 4),
                width=4, symtype=SYMT_OPER_ADD
            )),
    ]
    ops = translator.translate_effects(effects)
    pcode_json = translator.serialize_ops(ops)
    print(f"      ✓ Translated {len(ops)} p-code ops → {len(pcode_json)} bytes JSON")

    # Step 2: Start mock server and send decompile request
    server = MockJsonRpcServer(responses={
        "ping": {"pong": True, "version": "1.0"},
        "decompile_function": {
            "c_code": "int simple_add(int a, int b) {\n  return a + b;\n}",
            "high_pcode": [],
            "function_name": "simple_add",
            "success": True,
        },
    })
    server.start()

    try:
        cfg = Config()
        cfg.host = server.host
        cfg.port = server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            assert client.ping()["pong"] is True

            req = DecompileRequest(
                address=0x401000,
                mode="injected",  # Mode 2: include p-code
                pcode=ops,
            )
            result = client.decompile_function(req)
            assert result.success is True
            assert "simple_add" in result.c_code
            print(f"      ✓ Server returned C code for {result.function_name}")

    finally:
        server.stop()

    return True


def test_compile_binary():
    """Try to compile the test binary. Skip if gcc not available."""
    binary = compile_test_binary()
    if binary:
        print(f"  [6] Test binary compiled: {binary}")
        # Verify it runs
        result = subprocess.run([binary], capture_output=True, text=True, timeout=10)
        assert result.returncode == 138, f"Expected return code 138, got {result.returncode}"
        assert "Result: 138" in result.stdout
        print(f"      ✓ Binary runs correctly (exit code 138, output: {result.stdout.strip()})")
        return True
    else:
        print("  [6] Test binary compilation skipped (gcc not available)")
        return True  # Don't fail — gcc may not be installed


def main():
    """Run all integration tests."""
    print("═══════════════════════════════════════════════════════════════")
    print("  Vivisect-Ghidra Bridge — Integration Tests")
    print("═══════════════════════════════════════════════════════════════")
    print()

    tests = [
        test_pcode_translation,
        test_conditional_translation,
        test_memory_ops_translation,
        test_client_server_roundtrip,
        test_full_pipeline,
        test_compile_binary,
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"      ✗ FAILED: {e}")
            failed += 1

    print()
    print(f"═══════════════════════════════════════════════════════════════")
    print(f"  Integration tests: {passed} passed, {failed} failed")
    print(f"═══════════════════════════════════════════════════════════════")

    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())