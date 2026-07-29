"""
Symbolik effects/AST → Ghidra p-code translator.

This is the core intellectual contribution of the bridge: translating
Vivisect's effect-based symbolic IR into Ghidra's varnode-based p-code.

The translator walks each SymbolikEffect and emits a list of PcodeOp objects.
Each effect type maps to one or more p-code ops:

    SetVariable  → COPY (for simple values) or INT_ADD/INT_SUB/... (for operators)
    ReadMemory   → LOAD
    WriteMemory  → STORE
    CallFunction → CALL
    ConstrainPath→ CBRANCH

The AST (SymbolikBase subclasses) is walked recursively: complex expressions
like o_add(Var("eax"), Const(5, 4)) are decomposed into a sequence of p-code
ops with intermediate unique varnodes.

Key design decisions:
- Each sub-expression gets its own unique varnode (SSA-like, no reuse)
- Register names are preserved as reg_name on the varnode for debugging
- The translator maintains a unique counter for temporary varnodes
- Width (size in bytes) is tracked throughout — Ghidra p-code is size-explicit
"""

from __future__ import annotations

from typing import Any, Optional

from .models import (
    Varnode, VarnodeSpace, PcodeOp, PcodeOpcode, PcodeFunction,
)

# Vivisect symbolik imports — these are the actual classes from vivisect.symboliks
# We import them lazily so the module can be used without Vivisect installed
# (e.g., for unit testing with mock objects).

# Symtype constants from vivisect.const — duplicated here to avoid hard dependency
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

# ─── Operator symtype → p-code opcode mapping ───

OPERATOR_MAP = {
    SYMT_OPER_ADD: PcodeOpcode.INT_ADD,
    SYMT_OPER_SUB: PcodeOpcode.INT_SUB,
    SYMT_OPER_MUL: PcodeOpcode.INT_MULT,
    SYMT_OPER_DIV: PcodeOpcode.INT_DIV,
    SYMT_OPER_AND: PcodeOpcode.INT_AND,
    SYMT_OPER_OR: PcodeOpcode.INT_OR,
    SYMT_OPER_XOR: PcodeOpcode.INT_XOR,
    SYMT_OPER_MOD: PcodeOpcode.INT_REM,
    SYMT_OPER_LSHIFT: PcodeOpcode.INT_LEFT,
    SYMT_OPER_RSHIFT: PcodeOpcode.INT_RIGHT,
    SYMT_OPER_POW: PcodeOpcode.INT_MULT,  # no direct p-code equiv; closest is MULT
}

# ─── Constraint symtype → p-code opcode mapping ───

CONSTRAINT_MAP = {
    SYMT_CON_EQ: PcodeOpcode.INT_EQUAL,
    SYMT_CON_NE: PcodeOpcode.INT_NOTEQUAL,
    SYMT_CON_GT: PcodeOpcode.INT_SLESS,       # gt(v1,v2) ⟺ v2 < v1 (signed)
    SYMT_CON_GE: PcodeOpcode.INT_SLESSEQUAL,   # ge(v1,v2) ⟺ v2 <= v1 (signed)
    SYMT_CON_LT: PcodeOpcode.INT_SLESS,        # lt(v1,v2) ⟺ v1 < v2 (signed)
    SYMT_CON_LE: PcodeOpcode.INT_SLESSEQUAL,   # le(v1,v2) ⟺ v1 <= v2 (signed)
}

# ─── Register name normalization ───

# AMD64 register name → (space offset, size)
# These map Vivisect's register names to Ghidra's register space offsets.
# In a real Ghidra Program, register offsets are architecture-specific.
# For the translator, we use a simplified canonical mapping.
AMD64_REG_MAP = {
    # 8-byte registers
    "rax": (0, 8), "rcx": (8, 8), "rdx": (16, 8), "rbx": (24, 8),
    "rsp": (32, 8), "rbp": (40, 8), "rsi": (48, 8), "rdi": (56, 8),
    "r8":  (64, 8), "r9":  (72, 8), "r10": (80, 8), "r11": (88, 8),
    "r12": (96, 8), "r13": (104, 8), "r14": (112, 8), "r15": (120, 8),
    "rip": (128, 8),
    # 4-byte registers (sub-registers)
    "eax": (0, 4), "ecx": (8, 4), "edx": (16, 4), "ebx": (24, 4),
    "esp": (32, 4), "ebp": (40, 4), "esi": (48, 4), "edi": (56, 4),
    "r8d":  (64, 4), "r9d":  (72, 4), "r10d": (80, 4), "r11d": (88, 4),
    "r12d": (96, 4), "r13d": (104, 4), "r14d": (112, 4), "r15d": (120, 4),
    "eip": (128, 4),
    # 2-byte registers
    "ax": (0, 2), "cx": (8, 2), "dx": (16, 2), "bx": (24, 2),
    "sp": (32, 2), "bp": (40, 2), "si": (48, 2), "di": (56, 2),
    # 1-byte registers
    "al": (0, 1), "cl": (8, 1), "dl": (16, 1), "bl": (24, 1),
    "ah": (1, 1), "ch": (9, 1), "dh": (17, 1), "bh": (25, 1),
    # EFLAGS
    "eflags": (136, 8),
}

I386_REG_MAP = {
    "eax": (0, 4), "ecx": (4, 4), "edx": (8, 4), "ebx": (12, 4),
    "esp": (16, 4), "ebp": (20, 4), "esi": (24, 4), "edi": (28, 4),
    "eip": (32, 4), "eflags": (36, 4),
    # 2-byte
    "ax": (0, 2), "cx": (4, 2), "dx": (8, 2), "bx": (12, 2),
    "sp": (16, 2), "bp": (20, 2), "si": (24, 2), "di": (28, 2),
    # 1-byte
    "al": (0, 1), "cl": (4, 1), "dl": (8, 1), "bl": (12, 1),
    "ah": (1, 1), "ch": (5, 1), "dh": (9, 1), "bh": (13, 1),
}

# EFLAGS sub-field names used by the symbolik translator
EFLAGS_NAMES = {
    "eflags_gt", "eflags_eq", "eflags_lt", "eflags_ge", "eflags_le",
    "eflags_ne", "eflags_carry", "eflags_of", "eflags_pf", "eflags_sf",
    "eflags_zf", "eflags_af", "eflags_df",
}


class PcodeTranslator:
    """
    Translates Vivisect symbolik effects and AST nodes into Ghidra p-code ops.

    Usage:
        translator = PcodeTranslator(arch="amd64")
        ops = translator.translate_effects(effects)
        # ops is a list[PcodeOp]

    Or for a complete function:
        pcode_func = translator.translate_function(fva, ctx)
        # pcode_func is a PcodeFunction

    The translator is stateless between calls — each translate_* call
    resets the unique counter.
    """

    def __init__(self, arch: str = "amd64"):
        if arch not in ("amd64", "i386"):
            raise ValueError(f"Unsupported architecture: {arch}. Only amd64 and i386 are supported.")
        self.arch = arch
        self.reg_map = AMD64_REG_MAP if arch == "amd64" else I386_REG_MAP
        self.psize = 8 if arch == "amd64" else 4
        self._unique_counter = 0
        self._order_counter = 0

    def _reset(self):
        """Reset per-function state."""
        self._unique_counter = 0
        self._order_counter = 0

    def _next_unique(self, size: int) -> Varnode:
        """Allocate a new unique varnode of the given size."""
        vn = Varnode(space=VarnodeSpace.UNIQUE, offset=self._unique_counter, size=size)
        self._unique_counter += 1
        return vn

    def _next_order(self) -> int:
        """Get the next sub-instruction order number."""
        self._order_counter += 1
        return self._order_counter

    # ─── Varnode construction ───

    def _make_const(self, value: int, width: int) -> Varnode:
        """Create a constant varnode."""
        return Varnode(space=VarnodeSpace.CONST, offset=value, size=width)

    def _make_register(self, name: str, width: Optional[int] = None) -> Varnode:
        """
        Create a register varnode from a Vivisect register name.

        If the name is in the register map, use the canonical offset and size.
        If width is provided, override the size (for sub-register access).
        If the name is not in the map, treat it as a unique (unknown register).
        """
        name_lower = name.lower()

        # Handle eflags sub-fields
        if name_lower in EFLAGS_NAMES:
            offset = self.reg_map.get("eflags", (136, 8))[0]
            size = width or 1
            return Varnode(
                space=VarnodeSpace.REGISTER,
                offset=offset,
                size=size,
                reg_name=name,
            )

        if name_lower in self.reg_map:
            reg_offset, reg_size = self.reg_map[name_lower]
            size = width or reg_size
            return Varnode(
                space=VarnodeSpace.REGISTER,
                offset=reg_offset,
                size=size,
                reg_name=name_lower,
            )

        # Unknown register name — treat as unique variable
        # This handles stack pointer arithmetic, temporaries, etc.
        return Varnode(
            space=VarnodeSpace.UNIQUE,
            offset=hash(name) & 0xFFFFFFFF,
            size=width or self.psize,
            reg_name=name,
        )

    def _make_arg(self, idx: int, width: int) -> Varnode:
        """
        Create a varnode for a function argument.

        In Ghidra, function arguments live in the ram space at negative offsets
        from the function's base, or in register space for register-passed args.
        For simplicity, we use unique space with a special offset range.
        """
        return Varnode(
            space=VarnodeSpace.UNIQUE,
            offset=0x1000 + idx,
            size=width,
            reg_name=f"arg{idx}",
        )

    # ─── AST node → Varnode (with possible side-effect ops) ───

    def _translate_ast(self, node: Any, ops: list[PcodeOp], va: int) -> Varnode:
        """
        Translate a SymbolikBase AST node into p-code.

        Simple nodes (Var, Const, Arg) become varnodes directly.
        Complex nodes (Operator, Constraint, Call, Mem) generate
        intermediate p-code ops and return a unique varnode holding the result.

        This is the recursive heart of the translator.
        """
        if node is None:
            # Shouldn't happen in well-formed effects, but handle gracefully
            return self._make_const(0, self.psize)

        # Get the symtype — works for both real Vivisect objects and mock objects
        symtype = getattr(node, "symtype", None)

        # ─── Const ───
        if symtype == SYMT_CONST or isinstance(node, _MockConst):
            value = getattr(node, "value", 0)
            width = getattr(node, "width", self.psize)
            return self._make_const(value, width)

        # ─── Var ───
        if symtype == SYMT_VAR or isinstance(node, _MockVar):
            name = getattr(node, "name", "")
            width = getattr(node, "width", self.psize)
            return self._make_register(name, width)

        # ─── Arg ───
        if symtype == SYMT_ARG or isinstance(node, _MockArg):
            idx = getattr(node, "idx", 0)
            width = getattr(node, "width", self.psize)
            return self._make_arg(idx, width)

        # ─── Mem (memory read) ───
        if symtype == SYMT_MEM or isinstance(node, _MockMem):
            kids = getattr(node, "kids", [])
            addr_node = kids[0] if kids else None
            size_node = kids[1] if len(kids) > 1 else None

            # Translate the address expression first
            addr_vn = self._translate_ast(addr_node, ops, va)

            # Determine the load size
            size = self.psize
            if size_node is not None:
                size_val = getattr(size_node, "value", None)
                if size_val is not None:
                    size = size_val

            # LOAD: output = LOAD space_id, addr
            output = self._next_unique(size)
            # For LOAD, the first input is the address space indicator.
            # In Ghidra p-code, LOAD takes (space_id, address).
            # We use a const varnode as the space indicator (0 = ram/default).
            space_id = self._make_const(0, self.psize)
            op = PcodeOp(
                opcode=PcodeOpcode.LOAD,
                output=output,
                inputs=[space_id, addr_vn],
                va=va,
                order=self._next_order(),
            )
            ops.append(op)
            return output

        # ─── Call ───
        if symtype == SYMT_CALL or isinstance(node, _MockCall):
            kids = getattr(node, "kids", [])
            func_node = kids[0] if kids else None
            arg_nodes = kids[1:] if len(kids) > 1 else []
            width = getattr(node, "width", self.psize)

            # Translate the function target
            func_vn = self._translate_ast(func_node, ops, va)

            # Translate arguments
            arg_vns = [self._translate_ast(a, ops, va) for a in arg_nodes]

            # CALL: output = CALL func_addr, args...
            output = self._next_unique(width) if width > 0 else None
            op = PcodeOp(
                opcode=PcodeOpcode.CALL,
                output=output,
                inputs=[func_vn] + arg_vns,
                va=va,
                order=self._next_order(),
            )
            ops.append(op)
            return output or self._make_const(0, self.psize)

        # ─── o_sextend (sign extension) ───
        if symtype == SYMT_SEXT or isinstance(node, _MockSExtend):
            kids = getattr(node, "kids", [])
            val_node = kids[0] if kids else None
            tgt_node = kids[1] if len(kids) > 1 else None

            val_vn = self._translate_ast(val_node, ops, va)
            tgt_size = self.psize
            if tgt_node is not None:
                tgt_val = getattr(tgt_node, "value", None)
                if tgt_val is not None:
                    tgt_size = tgt_val

            output = self._next_unique(tgt_size)
            op = PcodeOp(
                opcode=PcodeOpcode.INT_SEXT,
                output=output,
                inputs=[val_vn],
                va=va,
                order=self._next_order(),
            )
            ops.append(op)
            return output

        # ─── cnot (boolean negate) ───
        if symtype == SYMT_NOT or isinstance(node, _MockCNot):
            kids = getattr(node, "kids", [])
            val_node = kids[0] if kids else None
            val_vn = self._translate_ast(val_node, ops, va)

            output = self._next_unique(1)  # boolean is 1 byte in Ghidra
            op = PcodeOp(
                opcode=PcodeOpcode.BOOL_NEGATE,
                output=output,
                inputs=[val_vn],
                va=va,
                order=self._next_order(),
            )
            ops.append(op)
            return output

        # ─── Operator (binary arithmetic/bitwise) ───
        if symtype and (symtype & SYMT_OPER) and not (symtype & SYMT_CON):
            return self._translate_operator(node, ops, va)

        # ─── Constraint (comparison) ───
        if symtype and (symtype & SYMT_CON):
            return self._translate_constraint(node, ops, va)

        # ─── Fallback: treat as opaque value ───
        # This handles LookupVar and any unknown node types
        name = str(node)
        width = getattr(node, "width", self.psize) or self.psize
        return self._make_register(name, width)

    def _translate_operator(self, node: Any, ops: list[PcodeOp], va: int) -> Varnode:
        """Translate a binary operator AST node into a p-code op."""
        symtype = getattr(node, "symtype", 0)
        kids = getattr(node, "kids", [])
        width = getattr(node, "width", self.psize) or self.psize

        v1_node = kids[0] if kids else None
        v2_node = kids[1] if len(kids) > 1 else None

        v1_vn = self._translate_ast(v1_node, ops, va)
        v2_vn = self._translate_ast(v2_node, ops, va)

        opcode = OPERATOR_MAP.get(symtype, PcodeOpcode.COPY)

        output = self._next_unique(width)
        op = PcodeOp(
            opcode=opcode,
            output=output,
            inputs=[v1_vn, v2_vn],
            va=va,
            order=self._next_order(),
        )
        ops.append(op)
        return output

    def _translate_constraint(self, node: Any, ops: list[PcodeOp], va: int) -> Varnode:
        """Translate a constraint AST node into a comparison p-code op."""
        symtype = getattr(node, "symtype", 0)
        kids = getattr(node, "kids", [])

        v1_node = kids[0] if kids else None
        v2_node = kids[1] if len(kids) > 1 else None

        v1_vn = self._translate_ast(v1_node, ops, va)
        v2_vn = self._translate_ast(v2_node, ops, va)

        # Determine the correct opcode based on the constraint type
        # Note: Vivisect's gt(v1, v2) means "v1 > v2", which in p-code
        # is INT_SLESS(v2, v1) — the operands are swapped for > and >=
        if symtype == SYMT_CON_GT:
            # gt(v1, v2) ⟺ v2 < v1
            opcode = PcodeOpcode.INT_SLESS
            inputs = [v2_vn, v1_vn]
        elif symtype == SYMT_CON_GE:
            # ge(v1, v2) ⟺ v2 <= v1
            opcode = PcodeOpcode.INT_SLESSEQUAL
            inputs = [v2_vn, v1_vn]
        else:
            opcode = CONSTRAINT_MAP.get(symtype, PcodeOpcode.INT_EQUAL)
            inputs = [v1_vn, v2_vn]

        # Comparison results are boolean (1 byte in Ghidra)
        output = self._next_unique(1)
        op = PcodeOp(
            opcode=opcode,
            output=output,
            inputs=inputs,
            va=va,
            order=self._next_order(),
        )
        ops.append(op)
        return output

    # ─── Effect → PcodeOp list ───

    def _get_efftype(self, effect: Any) -> int:
        """Get the effect type, handling both real and mock objects."""
        return getattr(effect, "efftype", -1)

    def _translate_set_variable(self, effect: Any, ops: list[PcodeOp]) -> None:
        """
        Translate a SetVariable effect.

        SetVariable(va, varname, symobj) means "assign symobj to varname".

        If symobj is a simple value (Var, Const, Arg), this becomes a COPY.
        If symobj is a complex expression, the expression is first translated
        into intermediate ops, and the final result is COPYed to the destination.
        """
        va = getattr(effect, "va", 0)
        varname = getattr(effect, "varname", "")
        symobj = getattr(effect, "symobj", None)

        # Translate the RHS expression
        result_vn = self._translate_ast(symobj, ops, va)

        # Create the destination varnode
        # Determine width from the symobj if possible
        width = getattr(symobj, "width", None) or self.psize
        dest_vn = self._make_register(varname, width)

        # If the result is already the same as the destination, skip the COPY
        if result_vn == dest_vn:
            return

        # Emit COPY dest = result
        op = PcodeOp(
            opcode=PcodeOpcode.COPY,
            output=dest_vn,
            inputs=[result_vn],
            va=va,
            order=self._next_order(),
        )
        ops.append(op)

    def _translate_read_memory(self, effect: Any, ops: list[PcodeOp]) -> None:
        """
        Translate a ReadMemory effect.

        ReadMemory(va, symaddr, symsize) — reads memory at symaddr.

        This generates a LOAD op. The result is stored in a unique varnode.
        Note: in the symbolik effect model, ReadMemory is somewhat passive —
        it records that a memory read happened. The actual value is typically
        consumed by a subsequent SetVariable. We emit the LOAD and leave
        the result in a unique varnode.
        """
        va = getattr(effect, "va", 0)
        symaddr = getattr(effect, "symaddr", None)
        symsize = getattr(effect, "symsize", None)

        addr_vn = self._translate_ast(symaddr, ops, va)

        # Determine load size
        size = self.psize
        if symsize is not None:
            size_val = getattr(symsize, "value", None)
            if size_val is not None:
                size = size_val

        space_id = self._make_const(0, self.psize)
        output = self._next_unique(size)
        op = PcodeOp(
            opcode=PcodeOpcode.LOAD,
            output=output,
            inputs=[space_id, addr_vn],
            va=va,
            order=self._next_order(),
        )
        ops.append(op)

    def _translate_write_memory(self, effect: Any, ops: list[PcodeOp]) -> None:
        """
        Translate a WriteMemory effect.

        WriteMemory(va, symaddr, symsize, symval) — writes symval to memory at symaddr.

        This generates a STORE op: STORE space_id, addr, val
        """
        va = getattr(effect, "va", 0)
        symaddr = getattr(effect, "symaddr", None)
        symsize = getattr(effect, "symsize", None)
        symval = getattr(effect, "symval", None)

        addr_vn = self._translate_ast(symaddr, ops, va)
        val_vn = self._translate_ast(symval, ops, va)

        space_id = self._make_const(0, self.psize)
        op = PcodeOp(
            opcode=PcodeOpcode.STORE,
            output=None,  # STORE has no output
            inputs=[space_id, addr_vn, val_vn],
            va=va,
            order=self._next_order(),
        )
        ops.append(op)

    def _translate_call_function(self, effect: Any, ops: list[PcodeOp]) -> None:
        """
        Translate a CallFunction effect.

        CallFunction(va, funcsym, argsyms) — calls function funcsym with args.

        This generates a CALL op. If argsyms is provided, each argument is
        translated first.
        """
        va = getattr(effect, "va", 0)
        funcsym = getattr(effect, "funcsym", None)
        argsyms = getattr(effect, "argsyms", None)

        func_vn = self._translate_ast(funcsym, ops, va)

        arg_vns = []
        if argsyms:
            arg_vns = [self._translate_ast(a, ops, va) for a in argsyms]

        op = PcodeOp(
            opcode=PcodeOpcode.CALL,
            output=None,  # call result is typically handled by a subsequent SetVariable
            inputs=[func_vn] + arg_vns,
            va=va,
            order=self._next_order(),
        )
        ops.append(op)

    def _translate_constrain_path(self, effect: Any, ops: list[PcodeOp]) -> None:
        """
        Translate a ConstrainPath effect.

        ConstrainPath(va, addrsym, cons) — conditional branch.

        This generates a CBRANCH op: CBRANCH target_addr, condition
        """
        va = getattr(effect, "va", 0)
        addrsym = getattr(effect, "addrsym", None)
        cons = getattr(effect, "cons", None)

        # Translate the condition expression
        cons_vn = self._translate_ast(cons, ops, va)

        # Translate the target address
        addr_vn = self._translate_ast(addrsym, ops, va)

        op = PcodeOp(
            opcode=PcodeOpcode.CBRANCH,
            output=None,
            inputs=[addr_vn, cons_vn],
            va=va,
            order=self._next_order(),
        )
        ops.append(op)

    def _translate_debug_effect(self, effect: Any, ops: list[PcodeOp]) -> None:
        """
        Translate a DebugEffect — unsupported instruction.

        We emit no p-code ops for debug effects, but we could emit a
        marker in the future. For now, silently skip.
        """
        pass

    # ─── Public API ───

    # Dispatch table for effect types
    _EFFECT_DISPATCH = {
        EFFTYPE_SETVAR:    "_translate_set_variable",
        EFFTYPE_READMEM:   "_translate_read_memory",
        EFFTYPE_WRITEMEM:  "_translate_write_memory",
        EFFTYPE_CALLFUNC:  "_translate_call_function",
        EFFTYPE_CONSTRAIN: "_translate_constrain_path",
        EFFTYPE_DEBUG:     "_translate_debug_effect",
    }

    def translate_effect(self, effect: Any) -> list[PcodeOp]:
        """
        Translate a single symbolik effect into p-code ops.

        Returns a list of PcodeOp objects (may be empty for DebugEffect).
        """
        ops: list[PcodeOp] = []
        efftype = self._get_efftype(effect)
        method_name = self._EFFECT_DISPATCH.get(efftype)
        if method_name is None:
            # Unknown effect type — skip
            return ops
        method = getattr(self, method_name)
        method(effect, ops)
        return ops

    def translate_effects(self, effects: list[Any], va_base: int = 0) -> list[PcodeOp]:
        """
        Translate a list of symbolik effects into p-code ops.

        This is the main entry point for translating a sequence of effects
        (e.g., from a single code block or a full path through a function).

        Args:
            effects: list of SymbolikEffect objects (or mock objects with
                     compatible attributes)
            va_base: base virtual address (used if individual effects don't
                     carry their own va)

        Returns:
            list of PcodeOp objects in order
        """
        self._reset()
        all_ops: list[PcodeOp] = []
        for effect in effects:
            # Ensure the effect has a va
            if not hasattr(effect, "va") or effect.va is None:
                effect.va = va_base
            all_ops.extend(self.translate_effect(effect))
        return all_ops

    def translate_function(
        self,
        fva: int,
        ctx: Any = None,
        name: str = "",
        arch: Optional[str] = None,
    ) -> PcodeFunction:
        """
        Translate a complete function into p-code.

        If a SymbolikAnalysisContext is provided, this will:
        1. Get the symbolik graph for the function
        2. Walk all paths, collecting effects
        3. Translate all effects into p-code ops

        If no context is provided, returns an empty PcodeFunction
        (caller must populate ops manually).

        Args:
            fva: function virtual address
            ctx: SymbolikAnalysisContext (from getSymbolikAnalysisContext(vw))
            name: function name (if known)
            arch: override architecture (default: self.arch)

        Returns:
            PcodeFunction containing all p-code ops
        """
        if arch is not None:
            self.arch = arch
            self.reg_map = AMD64_REG_MAP if arch == "amd64" else I386_REG_MAP
            self.psize = 8 if arch == "amd64" else 4

        self._reset()
        all_ops: list[PcodeOp] = []

        if ctx is not None:
            # Walk all symbolik paths and collect effects
            try:
                for emu, effects in ctx.walkSymbolikPaths(fva):
                    all_ops.extend(self.translate_effects(effects, va_base=fva))
            except Exception:
                # If the symbolik walk fails, return what we have
                pass

        return PcodeFunction(
            address=fva,
            name=name,
            ops=all_ops,
            arch=self.arch,
        )

    # ─── Utility ───

    def serialize_ops(self, ops: list[PcodeOp]) -> str:
        """Serialize a list of PcodeOps to JSON string for TCP transport."""
        import json
        return json.dumps([op.to_dict() for op in ops])

    @staticmethod
    def deserialize_ops(json_str: str) -> list[PcodeOp]:
        """Deserialize a JSON string back to a list of PcodeOps."""
        import json
        return [PcodeOp.from_dict(d) for d in json.loads(json_str)]


# ─── Mock classes for type detection ───
# These are used when the translator receives mock objects that don't
# have the real Vivisect symtype constants. They allow isinstance checks
# to work for testing without requiring Vivisect to be installed.

class _MockConst:    pass
class _MockVar:      pass
class _MockArg:      pass
class _MockMem:      pass
class _MockCall:     pass
class _MockSExtend:  pass
class _MockCNot:     pass