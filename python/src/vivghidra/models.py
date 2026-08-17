"""
Core data models for the p-code translation layer.

These dataclasses represent Ghidra p-code operations and varnodes in a
Python-native form that can be serialized to JSON for TCP transport.

Reference: Ghidra's PcodeOp and Varnode are Java classes in
ghidra.program.model.pcode. We mirror their structure here without
any Java dependency.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class VarnodeSpace(str, Enum):
    """Ghidra address spaces for varnodes."""
    CONST = "const"        # Immediate constant
    REGISTER = "register"  # Named register (offset maps to register ID)
    UNIQUE = "unique"      # Temporary / SSA unique varnode
    RAM = "ram"            # Main memory space
    BADSPACE = "badspace"  # Invalid / uninitialized


@dataclass(frozen=True)
class Varnode:
    """
    A p-code varnode — the fundamental data unit in Ghidra p-code.

    A varnode is identified by (space, offset, size). In Ghidra's Java model
    this is an Address + size. Here we keep it lightweight.

    For register varnodes, `offset` is the register's space offset and
    `reg_name` carries the human-readable register name (e.g., "RAX", "EAX").
    For unique varnodes, `offset` is a unique counter assigned by the translator.
    For const varnodes, `offset` is the constant value itself.
    For ram varnodes, `offset` is the memory address.
    """
    space: VarnodeSpace
    offset: int
    size: int
    reg_name: Optional[str] = None

    def to_dict(self) -> dict:
        d = {"space": self.space.value, "offset": self.offset, "size": self.size}
        if self.reg_name is not None:
            d["reg_name"] = self.reg_name
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "Varnode":
        return cls(
            space=VarnodeSpace(d["space"]),
            offset=d["offset"],
            size=d["size"],
            reg_name=d.get("reg_name"),
        )

    def __str__(self) -> str:
        if self.space == VarnodeSpace.CONST:
            return f"#{self.offset:#x}:{self.size}"
        if self.space == VarnodeSpace.REGISTER and self.reg_name:
            return f"{self.reg_name}:{self.size}"
        if self.space == VarnodeSpace.UNIQUE:
            return f"u{self.offset:#x}:{self.size}"
        return f"{self.space.value}[{self.offset:#x}]:{self.size}"


class PcodeOpcode(str, Enum):
    """
    Ghidra p-code opcodes.

    Reference: ghidra.program.model.pcode.PcodeOp — ~100+ ops.
    We enumerate the subset that the symbolik translator can emit.
    The integer values match Ghidra's opcode IDs for reference.
    """
    # Data movement
    COPY = "COPY"           # output = input
    LOAD = "LOAD"           # output = *input1 (space from input0)
    STORE = "STORE"         # *input1 = input2 (space from input0)

    # Integer arithmetic
    INT_ADD = "INT_ADD"     # output = input0 + input1
    INT_SUB = "INT_SUB"     # output = input0 - input1
    INT_MULT = "INT_MULT"   # output = input0 * input1
    INT_DIV = "INT_DIV"     # output = input0 / input1 (unsigned)
    INT_REM = "INT_REM"     # output = input0 % input1 (unsigned)
    INT_SDIV = "INT_SDIV"   # signed division
    INT_SREM = "INT_SREM"   # signed remainder

    # Bitwise
    INT_AND = "INT_AND"
    INT_OR = "INT_OR"
    INT_XOR = "INT_XOR"
    INT_NEGATE = "INT_NEGATE"   # output = ~input0

    # Shifts
    INT_LEFT = "INT_LEFT"       # output = input0 << input1
    INT_RIGHT = "INT_RIGHT"     # logical right shift
    INT_SRIGHT = "INT_SRIGHT"   # arithmetic right shift

    # Extension / truncation
    INT_SEXT = "INT_SEXT"       # sign-extend input0 to output size
    INT_ZEXT = "INT_ZEXT"       # zero-extend input0 to output size
    SUBPIECE = "SUBPIECE"       # output = input0[input1..input1+output.size]
    PIECE = "PIECE"             # output = concat(input0, input1)

    # Comparison (produce boolean)
    INT_EQUAL = "INT_EQUAL"
    INT_NOTEQUAL = "INT_NOTEQUAL"
    INT_LESS = "INT_LESS"           # unsigned less-than
    INT_SLESS = "INT_SLESS"         # signed less-than
    INT_LESSEQUAL = "INT_LESSEQUAL"
    INT_SLESSEQUAL = "INT_SLESSEQUAL"

    # Boolean ops
    BOOL_NEGATE = "BOOL_NEGATE"     # output = !input0
    BOOL_AND = "BOOL_AND"
    BOOL_OR = "BOOL_OR"

    # Control flow
    BRANCH = "BRANCH"       # unconditional jump to input0
    CBRANCH = "CBRANCH"     # if input1: jump to input0
    CALL = "CALL"           # call function at input0
    RETURN = "RETURN"       # return from function

    # Miscellaneous
    MULTIEQUAL = "MULTIEQUAL"   # phi node (SSA merge)
    INDIRECT = "INDIRECT"       # indirect effect marker
    CAST = "CAST"               # type cast (no-op semantically)


@dataclass
class PcodeOp:
    """
    A single p-code operation.

    Mirrors ghidra.program.model.pcode.PcodeOp. Each op has:
    - An opcode (what operation to perform)
    - An optional output varnode (where the result goes)
    - A list of input varnodes (operands)
    - A sequence number / address (where in the instruction stream this op lives)

    In Ghidra, the seqnum is (addr, order) where order disambiguates multiple
    p-code ops generated by a single instruction. We use `va` for the address
    and `order` for the sub-instruction index.
    """
    opcode: PcodeOpcode
    output: Optional[Varnode] = None
    inputs: list[Varnode] = field(default_factory=list)
    va: int = 0          # instruction address
    order: int = 0       # sub-instruction order (for multiple ops per instruction)

    def to_dict(self) -> dict:
        d = {
            "opcode": self.opcode.value,
            "output": self.output.to_dict() if self.output else None,
            "inputs": [v.to_dict() for v in self.inputs],
            "va": self.va,
            "order": self.order,
        }
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "PcodeOp":
        return cls(
            opcode=PcodeOpcode(d["opcode"]),
            output=Varnode.from_dict(d["output"]) if d.get("output") else None,
            inputs=[Varnode.from_dict(v) for v in d.get("inputs", [])],
            va=d.get("va", 0),
            order=d.get("order", 0),
        )

    def __str__(self) -> str:
        parts = []
        if self.output:
            parts.append(str(self.output))
            parts.append("=")
        parts.append(self.opcode.value)
        if self.inputs:
            parts.append("(")
            parts.append(", ".join(str(v) for v in self.inputs))
            parts.append(")")
        return " ".join(parts)


@dataclass
class PcodeFunction:
    """
    A complete p-code representation of a function.

    Contains the function's address, name, all p-code ops across all
    basic blocks, and metadata about the source function.
    """
    address: int
    name: str = ""
    ops: list[PcodeOp] = field(default_factory=list)
    arch: str = "amd64"        # source architecture
    param_count: int = 0       # number of parameters
    return_size: int = 0       # return value size in bytes (0 = void)

    def to_dict(self) -> dict:
        return {
            "address": self.address,
            "name": self.name,
            "ops": [op.to_dict() for op in self.ops],
            "arch": self.arch,
            "param_count": self.param_count,
            "return_size": self.return_size,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "PcodeFunction":
        return cls(
            address=d["address"],
            name=d.get("name", ""),
            ops=[PcodeOp.from_dict(o) for o in d.get("ops", [])],
            arch=d.get("arch", "amd64"),
            param_count=d.get("param_count", 0),
            return_size=d.get("return_size", 0),
        )

    def to_json(self) -> str:
        return json.dumps(self.to_dict())

    @classmethod
    def from_json(cls, s: str) -> "PcodeFunction":
        return cls.from_dict(json.loads(s))


# ─── Symbol info for Ghidra enrichment (Mode 1) ───

@dataclass
class SymbolInfo:
    """
    Symbol/type information extracted from Vivisect and sent to Ghidra
    to enrich the decompilation (Mode 1 — symbol-enriched decompilation).
    """
    name: str
    address: int
    type_name: str = ""       # e.g., "int", "char *", "void (*)(int)"
    size: int = 0             # size in bytes (0 = unknown)
    is_function: bool = False
    is_import: bool = False
    param_types: list[str] = field(default_factory=list)
    return_type: str = ""

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "SymbolInfo":
        return cls(**{k: d[k] for k in d if k in cls.__dataclass_fields__})


@dataclass
class DecompileRequest:
    """
    A decompilation request sent from the Vivisect extension to the
    Ghidra background process via JSON-RPC.
    """
    address: int
    mode: str = "standard"     # "standard", "enriched", "injected"
    symbols: list[SymbolInfo] = field(default_factory=list)
    pcode: list[PcodeOp] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.address:x}",
            "mode": self.mode,
            "symbols": [s.to_dict() for s in self.symbols],
            "pcode": [op.to_dict() for op in self.pcode],
        }


@dataclass
class DecompileResult:
    """
    The result returned from Ghidra after decompilation.
    """
    c_code: str = ""
    high_pcode: list[PcodeOp] = field(default_factory=list)
    function_name: str = ""
    success: bool = True
    error: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "DecompileResult":
        return cls(
            c_code=d.get("c_code", ""),
            high_pcode=[PcodeOp.from_dict(o) for o in d.get("high_pcode", [])],
            function_name=d.get("function_name", ""),
            success=d.get("success", True),
            error=d.get("error", ""),
        )


# ─── UI feature request models ───


@dataclass
class CommentRequest:
    """
    Request to set an end-of-line comment at a specific address in Ghidra.
    """
    address: int
    comment: str = ""

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.address:x}",
            "comment": self.comment,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "CommentRequest":
        addr = d.get("address", "0x0")
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        return cls(address=addr, comment=d.get("comment", ""))


@dataclass
class RenameRequest:
    """
    Request to rename a symbol (function or data) at a specific address.
    """
    address: int
    name: str
    is_function: bool = True

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.address:x}",
            "name": self.name,
            "is_function": self.is_function,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "RenameRequest":
        addr = d.get("address", "0x0")
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        return cls(
            address=addr,
            name=d.get("name", ""),
            is_function=d.get("is_function", True),
        )


@dataclass
class SignatureRequest:
    """
    Request to set a full function signature (name, return type, params, calling convention).
    """
    address: int
    name: str = ""
    return_type: str = "void"
    param_types: list[str] = field(default_factory=list)
    calling_conv: str = "cdecl"

    def to_dict(self) -> dict:
        return {
            "address": f"0x{self.address:x}",
            "name": self.name,
            "return_type": self.return_type,
            "param_types": self.param_types,
            "calling_conv": self.calling_conv,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "SignatureRequest":
        addr = d.get("address", "0x0")
        if isinstance(addr, str):
            addr = int(addr, 16) if addr.startswith("0x") else int(addr)
        return cls(
            address=addr,
            name=d.get("name", ""),
            return_type=d.get("return_type", "void"),
            param_types=d.get("param_types", []),
            calling_conv=d.get("calling_conv", "cdecl"),
        )