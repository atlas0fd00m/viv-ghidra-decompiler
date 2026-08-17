"""
Test fixtures for the Vivisect–Ghidra bridge unit tests.

Provides mock objects that mimic the Vivisect symbolik API without
requiring Vivisect to be installed. This allows the p-code translator
tests to run standalone.
"""

import sys
import os
import pytest
import socket
import threading
import json
import tempfile

# Add the src directory to the path so we can import vivghidra
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))


# ─── Mock symbolik AST nodes ───
# These mimic the structure of vivisect.symboliks.common classes
# without requiring the vivisect package.

# Symtype constants (duplicated from vivisect.const)
EFFTYPE_DEBUG = 0
EFFTYPE_SETVAR = 1
EFFTYPE_READMEM = 2
EFFTYPE_WRITEMEM = 3
EFFTYPE_CALLFUNC = 4
EFFTYPE_CONSTRAIN = 5

SYMT_VAR = 0
SYMT_ARG = 1
SYMT_CALL = 2
SYMT_MEM = 3
SYMT_SEXT = 4
SYMT_CONST = 5
SYMT_LOOKUP = 6
SYMT_NOT = 7

SYMT_OPER = 0x00010000
SYMT_OPER_ADD = SYMT_OPER | 1
SYMT_OPER_SUB = SYMT_OPER | 2
SYMT_OPER_MUL = SYMT_OPER | 3
SYMT_OPER_DIV = SYMT_OPER | 4
SYMT_OPER_AND = SYMT_OPER | 5
SYMT_OPER_OR = SYMT_OPER | 6
SYMT_OPER_XOR = SYMT_OPER | 7
SYMT_OPER_MOD = SYMT_OPER | 8
SYMT_OPER_LSHIFT = SYMT_OPER | 9
SYMT_OPER_RSHIFT = SYMT_OPER | 10
SYMT_OPER_POW = SYMT_OPER | 11

SYMT_CON = 0x00020000
SYMT_CON_EQ = SYMT_CON | 1
SYMT_CON_NE = SYMT_CON | 2
SYMT_CON_GT = SYMT_CON | 3
SYMT_CON_GE = SYMT_CON | 4
SYMT_CON_LT = SYMT_CON | 5
SYMT_CON_LE = SYMT_CON | 6


class MockConst:
    """Mock of vivisect.symboliks.common.Const"""
    symtype = SYMT_CONST
    discrete = True

    def __init__(self, value, width=4, ptrname=None, constname=None):
        self.value = value % (2 ** (width * 8))
        self.width = width
        self.ptrname = ptrname
        self.constname = constname

    def __repr__(self):
        return f"Const(0x{self.value:x},{self.width})"

    def __str__(self):
        if self.value > 4096:
            return f"0x{self.value:08x}"
        return str(self.value)

    def getWidth(self):
        return self.width


class MockVar:
    """Mock of vivisect.symboliks.common.Var"""
    symtype = SYMT_VAR
    discrete = False

    def __init__(self, name, width=4):
        self.name = name
        self.width = width
        self.kids = []

    def __repr__(self):
        return f'Var("{self.name}", width={self.width})'

    def __str__(self):
        return self.name

    def getWidth(self):
        return self.width


class MockArg:
    """Mock of vivisect.symboliks.common.Arg"""
    symtype = SYMT_ARG
    discrete = False

    def __init__(self, idx, width=4):
        self.idx = idx
        self.width = width
        self.kids = []

    def __repr__(self):
        return f"Arg({self.idx},width={self.width})"

    def __str__(self):
        return f"arg{self.idx}"

    def getWidth(self):
        return self.width


class MockOperator:
    """Mock of vivisect.symboliks.common.Operator subclasses (o_add, o_sub, etc.)"""
    symtype = SYMT_OPER  # overridden per instance
    commutative = False

    def __init__(self, v1, v2, width=4, symtype=SYMT_OPER_ADD):
        self.symtype = symtype
        self.width = width
        self.kids = [v1, v2]

    def __repr__(self):
        return f"MockOperator({self.symtype:#x},{self.kids[0]!r},{self.kids[1]!r},{self.width})"

    def getWidth(self):
        return self.width


class MockConstraint:
    """Mock of vivisect.symboliks.common.Constraint subclasses (eq, ne, gt, etc.)"""
    symtype = SYMT_CON  # overridden per instance

    def __init__(self, v1, v2, width=4, symtype=SYMT_CON_EQ):
        self.symtype = symtype
        self.width = width
        self.kids = [v1, v2]

    def __repr__(self):
        return f"MockConstraint({self.symtype:#x},{self.kids[0]!r},{self.kids[1]!r})"

    def getWidth(self):
        return self.kids[0].getWidth() if hasattr(self.kids[0], "getWidth") else self.width


class MockMem:
    """Mock of vivisect.symboliks.common.Mem"""
    symtype = SYMT_MEM
    discrete = False

    def __init__(self, symaddr, symsize):
        self.kids = [symaddr, symsize]

    def __repr__(self):
        return f"Mem({self.kids[0]!r},{self.kids[1]!r})"

    def getWidth(self):
        return self.kids[1].value if hasattr(self.kids[1], "value") else 4


class MockCall:
    """Mock of vivisect.symboliks.common.Call"""
    symtype = SYMT_CALL
    discrete = False

    def __init__(self, funcsym, width=4, argsyms=None):
        self.width = width
        self.kids = [funcsym] + (argsyms or [])

    def __repr__(self):
        return f"Call({self.kids[0]!r},{self.width})"

    def getWidth(self):
        return self.width


class MockCNot:
    """Mock of vivisect.symboliks.common.cnot"""
    symtype = SYMT_NOT

    def __init__(self, v1):
        self.kids = [v1]
        self.width = v1.width if hasattr(v1, "width") else 1

    def getWidth(self):
        return self.width


class MockSExtend:
    """Mock of vivisect.symboliks.common.o_sextend"""
    symtype = SYMT_SEXT

    def __init__(self, v1, tgtsz):
        self.kids = [v1, tgtsz]

    def getWidth(self):
        return self.kids[1].value if hasattr(self.kids[1], "value") else 8


# ─── Mock symbolik effects ───

class MockSetVariable:
    """Mock of vivisect.symboliks.effects.SetVariable"""
    efftype = EFFTYPE_SETVAR

    def __init__(self, va, varname, symobj):
        self.va = va
        self.varname = varname
        self.symobj = symobj

    def __repr__(self):
        return f"SetVariable(0x{self.va:08x}, {self.varname}, {self.symobj!r})"

    def __str__(self):
        return f"{self.varname} = {self.symobj}"


class MockReadMemory:
    """Mock of vivisect.symboliks.effects.ReadMemory"""
    efftype = EFFTYPE_READMEM

    def __init__(self, va, symaddr, symsize):
        self.va = va
        self.symaddr = symaddr
        self.symsize = symsize

    def __repr__(self):
        return f"ReadMemory(0x{self.va:08x}, {self.symaddr!r}, {self.symsize!r})"


class MockWriteMemory:
    """Mock of vivisect.symboliks.effects.WriteMemory"""
    efftype = EFFTYPE_WRITEMEM

    def __init__(self, va, symaddr, symsize, symval):
        self.va = va
        self.symaddr = symaddr
        self.symsize = symsize
        self.symval = symval

    def __repr__(self):
        return f"WriteMemory(0x{self.va:08x}, {self.symaddr!r}, {self.symsize!r}, {self.symval!r})"


class MockCallFunction:
    """Mock of vivisect.symboliks.effects.CallFunction"""
    efftype = EFFTYPE_CALLFUNC

    def __init__(self, va, funcsym, argsyms=None):
        self.va = va
        self.funcsym = funcsym
        self.argsyms = argsyms

    def __repr__(self):
        return f"CallFunction(0x{self.va:08x}, {self.funcsym!r}, {self.argsyms})"


class MockConstrainPath:
    """Mock of vivisect.symboliks.effects.ConstrainPath"""
    efftype = EFFTYPE_CONSTRAIN

    def __init__(self, va, addrsym, cons):
        self.va = va
        self.addrsym = addrsym
        self.cons = cons

    def __repr__(self):
        return f"ConstrainPath(0x{self.va:08x}, {self.addrsym!r}, {self.cons!r})"


class MockDebugEffect:
    """Mock of vivisect.symboliks.effects.DebugEffect"""
    efftype = EFFTYPE_DEBUG

    def __init__(self, va, msg=""):
        self.va = va
        self.msg = msg


# ─── Mock VivWorkspace ───

class MockVivWorkspace:
    """
    Minimal mock of vivisect.VivWorkspace for symbol extractor tests.
    """
    psize = 8  # amd64

    def __init__(self):
        self._functions = {}  # fva → {name, api, args, is_import}
        self._names = {}      # va → name
        self._xrefs = {}      # va → [(from, to, ...), ...]

    def getFunctions(self):
        return list(self._functions.keys())

    def isFunction(self, va):
        return va in self._functions

    def getName(self, va):
        return self._names.get(va)

    def getFunctionArgs(self, fva):
        return self._functions.get(fva, {}).get("args", [])

    def getFunctionApi(self, fva):
        return self._functions.get(fva, {}).get("api")

    def getXrefsFrom(self, va):
        return self._xrefs.get(va, [])

    def getLocation(self, va):
        info = self._functions.get(va, {})
        if info.get("is_import"):
            # (lva, lsize, ltype, linfo) — linfo=2 means LOC_IMPORT
            return (va, 0, 0, 2)
        return None

    def add_function(self, fva, name=None, api=None, args=None, is_import=False):
        self._functions[fva] = {
            "name": name or f"sub_{fva:x}",
            "api": api or ("void", "", "cdecl", name or f"sub_{fva:x}", []),
            "args": args or [],
            "is_import": is_import,
        }
        self._names[fva] = name or f"sub_{fva:x}"

    def add_xref(self, from_va, to_va):
        self._xrefs.setdefault(from_va, []).append((from_va, 0, to_va))


# ─── Mock JSON-RPC server for GhidraClient tests ───

class MockJsonRpcServer:
    """
    A minimal TCP server that speaks the newline-delimited JSON-RPC protocol.
    Used to test GhidraClient without a real Ghidra instance.
    """

    def __init__(self, responses: dict = None):
        """
        Args:
            responses: dict mapping method names to response dicts.
                       If a method isn't in the dict, returns a default.
        """
        self.responses = responses or {}
        self._sock = None
        self._thread = None
        self._running = False
        self.host = "127.0.0.1"
        self.port = 0  # will be assigned by OS

    def start(self):
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._sock.bind((self.host, 0))
        self._sock.listen(1)
        self.port = self._sock.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=2)

    def _serve(self):
        while self._running:
            try:
                conn, _ = self._sock.accept()
                threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()
            except OSError:
                break

    def _handle_client(self, conn):
        try:
            buf = b""
            while True:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    request = json.loads(line.decode("utf-8"))
                    method = request.get("method", "")
                    result = self.responses.get(method, {"ok": True})
                    response = {"result": result}
                    conn.sendall((json.dumps(response) + "\n").encode("utf-8"))
        except (OSError, json.JSONDecodeError):
            pass
        finally:
            conn.close()


# ─── Pytest fixtures ───

@pytest.fixture
def amd64_translator():
    """A PcodeTranslator configured for amd64."""
    from vivghidra.pcode_translator import PcodeTranslator
    return PcodeTranslator(arch="amd64")


@pytest.fixture
def i386_translator():
    """A PcodeTranslator configured for i386."""
    from vivghidra.pcode_translator import PcodeTranslator
    return PcodeTranslator(arch="i386")


@pytest.fixture
def mock_vw():
    """A MockVivWorkspace with a few functions populated."""
    vw = MockVivWorkspace()
    vw.add_function(0x401000, name="main",
                    api=("int", "ret", "cdecl", "main", [("int", "argc"), ("char **", "argv")]),
                    args=[("int", "argc"), ("char **", "argv")])
    vw.add_function(0x401200, name="printf",
                    api=("int", "ret", "cdecl", "printf", [("const char *", "fmt")]),
                    args=[("const char *", "fmt")],
                    is_import=True)
    vw.add_xref(0x401000, 0x401200)
    return vw


@pytest.fixture
def mock_server():
    """A MockJsonRpcServer with standard responses."""
    server = MockJsonRpcServer(responses={
        "ping": {"pong": True, "version": "1.0"},
        "get_status": {"program_loaded": True, "program_name": "test_binary"},
        "decompile_function": {
            "c_code": "int main(int argc, char **argv) {\n  return 0;\n}\n",
            "high_pcode": [],
            "function_name": "main",
            "success": True,
        },
        "get_function_list": {
            "functions": [{"name": "main", "address": "0x401000", "size": 100}]
        },
    })
    server.start()
    yield server
    server.stop()


@pytest.fixture
def mock_server_ui():
    """A MockJsonRpcServer with responses for UI feature methods."""
    server = MockJsonRpcServer(responses={
        "set_comment": {"success": True},
        "rename_symbol": {"success": True},
        "set_signature": {"success": True},
    })
    server.start()
    yield server
    server.stop()