"""
Unit tests for the p-code translator.

Tests the translation of Vivisect symbolik effects and AST nodes
into Ghidra p-code operations using mock objects (no Vivisect required).
"""

import json
import pytest

from vivghidra.models import (
    Varnode, VarnodeSpace, PcodeOp, PcodeOpcode, PcodeFunction,
    SymbolInfo, DecompileRequest, DecompileResult,
)
from vivghidra.pcode_translator import PcodeTranslator

# Import mock objects from conftest
from conftest import (
    MockConst, MockVar, MockArg, MockOperator, MockConstraint,
    MockMem, MockCall, MockCNot, MockSExtend,
    MockSetVariable, MockReadMemory, MockWriteMemory,
    MockCallFunction, MockConstrainPath, MockDebugEffect,
    SYMT_OPER_ADD, SYMT_OPER_SUB, SYMT_OPER_MUL, SYMT_OPER_AND,
    SYMT_OPER_OR, SYMT_OPER_XOR, SYMT_OPER_LSHIFT, SYMT_OPER_RSHIFT,
    SYMT_OPER_MOD, SYMT_OPER_DIV,
    SYMT_CON_EQ, SYMT_CON_NE, SYMT_CON_GT, SYMT_CON_LT, SYMT_CON_GE, SYMT_CON_LE,
)


# ═══════════════════════════════════════════════════════════════
# Varnode tests
# ═══════════════════════════════════════════════════════════════

class TestVarnode:
    """Tests for the Varnode dataclass."""

    def test_const_varnode(self):
        vn = Varnode(space=VarnodeSpace.CONST, offset=42, size=4)
        assert vn.space == VarnodeSpace.CONST
        assert vn.offset == 42
        assert vn.size == 4
        assert vn.reg_name is None

    def test_register_varnode(self):
        vn = Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax")
        assert vn.space == VarnodeSpace.REGISTER
        assert vn.reg_name == "rax"

    def test_unique_varnode(self):
        vn = Varnode(space=VarnodeSpace.UNIQUE, offset=5, size=4)
        assert vn.space == VarnodeSpace.UNIQUE
        assert vn.offset == 5

    def test_ram_varnode(self):
        vn = Varnode(space=VarnodeSpace.RAM, offset=0x401000, size=8)
        assert vn.space == VarnodeSpace.RAM
        assert vn.offset == 0x401000

    def test_to_dict_and_back(self):
        vn = Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax")
        d = vn.to_dict()
        assert d["space"] == "register"
        assert d["reg_name"] == "rax"
        vn2 = Varnode.from_dict(d)
        assert vn2 == vn

    def test_str_const(self):
        vn = Varnode(space=VarnodeSpace.CONST, offset=0x100, size=4)
        assert "0x100" in str(vn)

    def test_str_register(self):
        vn = Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax")
        assert "rax" in str(vn)

    def test_str_unique(self):
        vn = Varnode(space=VarnodeSpace.UNIQUE, offset=3, size=4)
        s = str(vn)
        assert "u" in s
        assert "3" in s

    def test_frozen(self):
        """Varnode is frozen — should not be mutable."""
        vn = Varnode(space=VarnodeSpace.CONST, offset=1, size=4)
        with pytest.raises(AttributeError):
            vn.offset = 2


# ═══════════════════════════════════════════════════════════════
# PcodeOp tests
# ═══════════════════════════════════════════════════════════════

class TestPcodeOp:
    """Tests for the PcodeOp dataclass."""

    def test_copy_op(self):
        out = Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax")
        inp = Varnode(space=VarnodeSpace.CONST, offset=42, size=8)
        op = PcodeOp(opcode=PcodeOpcode.COPY, output=out, inputs=[inp], va=0x401000)
        assert op.opcode == PcodeOpcode.COPY
        assert op.output == out
        assert len(op.inputs) == 1
        assert op.va == 0x401000

    def test_no_output(self):
        """STORE ops have no output."""
        op = PcodeOp(opcode=PcodeOpcode.STORE, output=None,
                     inputs=[Varnode(space=VarnodeSpace.CONST, offset=0, size=8)])
        assert op.output is None

    def test_to_dict_and_back(self):
        op = PcodeOp(
            opcode=PcodeOpcode.INT_ADD,
            output=Varnode(space=VarnodeSpace.UNIQUE, offset=0, size=8),
            inputs=[
                Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax"),
                Varnode(space=VarnodeSpace.CONST, offset=1, size=8),
            ],
            va=0x401000,
            order=2,
        )
        d = op.to_dict()
        assert d["opcode"] == "INT_ADD"
        assert d["va"] == 0x401000
        op2 = PcodeOp.from_dict(d)
        assert op2.opcode == PcodeOpcode.INT_ADD
        assert op2.va == 0x401000
        assert len(op2.inputs) == 2

    def test_str_representation(self):
        op = PcodeOp(
            opcode=PcodeOpcode.COPY,
            output=Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax"),
            inputs=[Varnode(space=VarnodeSpace.CONST, offset=42, size=8)],
        )
        s = str(op)
        assert "COPY" in s
        assert "rax" in s


# ═══════════════════════════════════════════════════════════════
# PcodeFunction tests
# ═══════════════════════════════════════════════════════════════

class TestPcodeFunction:
    """Tests for the PcodeFunction dataclass."""

    def test_empty_function(self):
        pf = PcodeFunction(address=0x401000, name="test")
        assert pf.address == 0x401000
        assert pf.name == "test"
        assert len(pf.ops) == 0

    def test_to_json_and_back(self):
        pf = PcodeFunction(
            address=0x401000,
            name="main",
            ops=[
                PcodeOp(opcode=PcodeOpcode.COPY,
                        output=Varnode(space=VarnodeSpace.REGISTER, offset=0, size=8, reg_name="rax"),
                        inputs=[Varnode(space=VarnodeSpace.CONST, offset=0, size=8)],
                        va=0x401000),
            ],
            arch="amd64",
            param_count=2,
            return_size=4,
        )
        s = pf.to_json()
        pf2 = PcodeFunction.from_json(s)
        assert pf2.address == 0x401000
        assert pf2.name == "main"
        assert len(pf2.ops) == 1
        assert pf2.arch == "amd64"


# ═══════════════════════════════════════════════════════════════
# PcodeTranslator — AST node tests
# ═══════════════════════════════════════════════════════════════

class TestTranslatorConst:
    """Tests for Const AST node translation."""

    def test_const_to_varnode(self, amd64_translator):
        node = MockConst(42, 4)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        assert vn.space == VarnodeSpace.CONST
        assert vn.offset == 42
        assert vn.size == 4
        assert len(ops) == 0  # const doesn't generate ops


class TestTranslatorVar:
    """Tests for Var AST node translation."""

    def test_known_register(self, amd64_translator):
        node = MockVar("rax", 8)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        assert vn.space == VarnodeSpace.REGISTER
        assert vn.reg_name == "rax"
        assert vn.size == 8
        assert len(ops) == 0

    def test_subregister_eax(self, amd64_translator):
        node = MockVar("eax", 4)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        assert vn.space == VarnodeSpace.REGISTER
        assert vn.reg_name == "eax"
        assert vn.size == 4

    def test_eflags_name(self, amd64_translator):
        node = MockVar("eflags_zf", 1)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        assert vn.space == VarnodeSpace.REGISTER
        assert vn.reg_name == "eflags_zf"

    def test_unknown_var_becomes_unique(self, amd64_translator):
        node = MockVar("some_temp_var", 4)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        # Unknown register names become unique varnodes
        assert vn.reg_name == "some_temp_var"


class TestTranslatorArg:
    """Tests for Arg AST node translation."""

    def test_arg_varnode(self, amd64_translator):
        node = MockArg(0, 8)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        assert vn.space == VarnodeSpace.UNIQUE
        assert vn.reg_name == "arg0"
        assert vn.size == 8

    def test_arg_offset_increases(self, amd64_translator):
        node0 = MockArg(0, 8)
        node1 = MockArg(1, 8)
        ops = []
        vn0 = amd64_translator._translate_ast(node0, ops, 0x401000)
        vn1 = amd64_translator._translate_ast(node1, ops, 0x401000)
        assert vn0.offset != vn1.offset


# ═══════════════════════════════════════════════════════════════
# PcodeTranslator — Operator tests
# ═══════════════════════════════════════════════════════════════

class TestTranslatorOperators:
    """Tests for binary operator AST node translation."""

    @pytest.mark.parametrize("symtype,expected_opcode", [
        (SYMT_OPER_ADD, PcodeOpcode.INT_ADD),
        (SYMT_OPER_SUB, PcodeOpcode.INT_SUB),
        (SYMT_OPER_MUL, PcodeOpcode.INT_MULT),
        (SYMT_OPER_DIV, PcodeOpcode.INT_DIV),
        (SYMT_OPER_AND, PcodeOpcode.INT_AND),
        (SYMT_OPER_OR, PcodeOpcode.INT_OR),
        (SYMT_OPER_XOR, PcodeOpcode.INT_XOR),
        (SYMT_OPER_MOD, PcodeOpcode.INT_REM),
        (SYMT_OPER_LSHIFT, PcodeOpcode.INT_LEFT),
        (SYMT_OPER_RSHIFT, PcodeOpcode.INT_RIGHT),
    ])
    def test_operator_mapping(self, amd64_translator, symtype, expected_opcode):
        """Each operator symtype maps to the correct p-code opcode."""
        v1 = MockVar("rax", 8)
        v2 = MockConst(5, 8)
        node = MockOperator(v1, v2, width=8, symtype=symtype)
        ops = []
        result_vn = amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == expected_opcode
        assert ops[0].output is not None
        assert ops[0].output.space == VarnodeSpace.UNIQUE
        assert len(ops[0].inputs) == 2
        assert ops[0].va == 0x401000

    def test_nested_operators(self, amd64_translator):
        """Nested operators generate multiple intermediate ops."""
        # (rax + 5) * rbx
        inner = MockOperator(MockVar("rax", 8), MockConst(5, 8), width=8, symtype=SYMT_OPER_ADD)
        outer = MockOperator(inner, MockVar("rbx", 8), width=8, symtype=SYMT_OPER_MUL)
        ops = []
        result_vn = amd64_translator._translate_ast(outer, ops, 0x401000)

        # Should generate 2 ops: INT_ADD then INT_MULT
        assert len(ops) == 2
        assert ops[0].opcode == PcodeOpcode.INT_ADD
        assert ops[1].opcode == PcodeOpcode.INT_MULT
        # The INT_MULT should use the output of INT_ADD as an input
        assert ops[0].output in ops[1].inputs

    def test_operator_with_const_inputs(self, amd64_translator):
        """Operator with two const inputs still generates an op."""
        node = MockOperator(MockConst(1, 4), MockConst(2, 4), width=4, symtype=SYMT_OPER_ADD)
        ops = []
        amd64_translator._translate_ast(node, ops, 0x401000)
        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.INT_ADD
        assert all(v.space == VarnodeSpace.CONST for v in ops[0].inputs)


# ═══════════════════════════════════════════════════════════════
# PcodeTranslator — Constraint tests
# ═══════════════════════════════════════════════════════════════

class TestTranslatorConstraints:
    """Tests for constraint AST node translation."""

    @pytest.mark.parametrize("symtype,expected_opcode", [
        (SYMT_CON_EQ, PcodeOpcode.INT_EQUAL),
        (SYMT_CON_NE, PcodeOpcode.INT_NOTEQUAL),
        (SYMT_CON_LT, PcodeOpcode.INT_SLESS),
        (SYMT_CON_LE, PcodeOpcode.INT_SLESSEQUAL),
    ])
    def test_direct_constraints(self, amd64_translator, symtype, expected_opcode):
        """Constraints like eq, ne, lt, le map directly."""
        v1 = MockVar("eax", 4)
        v2 = MockConst(0, 4)
        node = MockConstraint(v1, v2, width=4, symtype=symtype)
        ops = []
        amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == expected_opcode
        assert ops[0].output.size == 1  # boolean result

    def test_gt_swaps_operands(self, amd64_translator):
        """gt(v1, v2) should produce INT_SLESS(v2, v1) — operands swapped."""
        v1 = MockVar("eax", 4)
        v2 = MockConst(0, 4)
        node = MockConstraint(v1, v2, width=4, symtype=SYMT_CON_GT)
        ops = []
        amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.INT_SLESS
        # First input should be v2 (the const), second should be v1 (the var)
        assert ops[0].inputs[0].space == VarnodeSpace.CONST   # v2
        assert ops[0].inputs[1].space == VarnodeSpace.REGISTER  # v1

    def test_ge_swaps_operands(self, amd64_translator):
        """ge(v1, v2) should produce INT_SLESSEQUAL(v2, v1) — operands swapped."""
        v1 = MockVar("eax", 4)
        v2 = MockConst(0, 4)
        node = MockConstraint(v1, v2, width=4, symtype=SYMT_CON_GE)
        ops = []
        amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.INT_SLESSEQUAL
        assert ops[0].inputs[0].space == VarnodeSpace.CONST   # v2
        assert ops[0].inputs[1].space == VarnodeSpace.REGISTER  # v1


# ═══════════════════════════════════════════════════════════════
# PcodeTranslator — Memory and Call tests
# ═══════════════════════════════════════════════════════════════

class TestTranslatorMemory:
    """Tests for Mem AST node and ReadMemory/WriteMemory effects."""

    def test_mem_ast_generates_load(self, amd64_translator):
        """Mem(addr, size) AST node generates a LOAD op."""
        addr = MockConst(0x601000, 8)
        size = MockConst(4, 4)
        node = MockMem(addr, size)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.LOAD
        assert ops[0].output is not None
        assert ops[0].output.space == VarnodeSpace.UNIQUE

    def test_read_memory_effect(self, amd64_translator):
        """ReadMemory effect generates a LOAD op."""
        addr = MockConst(0x601000, 8)
        size = MockConst(4, 4)
        effect = MockReadMemory(0x401000, addr, size)
        ops = amd64_translator.translate_effect(effect)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.LOAD
        assert ops[0].va == 0x401000

    def test_write_memory_effect(self, amd64_translator):
        """WriteMemory effect generates a STORE op."""
        addr = MockConst(0x601000, 8)
        size = MockConst(4, 4)
        val = MockVar("eax", 4)
        effect = MockWriteMemory(0x401000, addr, size, val)
        ops = amd64_translator.translate_effect(effect)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.STORE
        assert ops[0].output is None  # STORE has no output
        assert len(ops[0].inputs) == 3  # space_id, addr, val


class TestTranslatorCall:
    """Tests for Call AST node and CallFunction effect."""

    def test_call_ast(self, amd64_translator):
        """Call(funcsym, width, args) generates a CALL op."""
        func = MockConst(0x401200, 8)
        arg1 = MockVar("edi", 4)
        node = MockCall(func, width=4, argsyms=[arg1])
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.CALL
        assert ops[0].output is not None  # call returns a value
        assert len(ops[0].inputs) == 2  # func + 1 arg

    def test_call_function_effect(self, amd64_translator):
        """CallFunction effect generates a CALL op."""
        func = MockConst(0x401200, 8)
        arg1 = MockVar("edi", 4)
        effect = MockCallFunction(0x401000, func, argsyms=[arg1])
        ops = amd64_translator.translate_effect(effect)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.CALL
        assert ops[0].va == 0x401000


class TestTranslatorConstrainPath:
    """Tests for ConstrainPath effect."""

    def test_constrain_path_generates_cbranch(self, amd64_translator):
        """ConstrainPath effect generates a CBRANCH op."""
        target = MockConst(0x401050, 8)
        condition = MockConstraint(
            MockVar("eax", 4), MockConst(0, 4),
            width=4, symtype=SYMT_CON_EQ,
        )
        effect = MockConstrainPath(0x401000, target, condition)
        ops = amd64_translator.translate_effect(effect)

        # Should generate: 1 comparison op + 1 CBRANCH
        assert len(ops) == 2
        assert ops[0].opcode == PcodeOpcode.INT_EQUAL
        assert ops[1].opcode == PcodeOpcode.CBRANCH
        assert ops[1].va == 0x401000


# ═══════════════════════════════════════════════════════════════
# PcodeTranslator — Effect translation tests
# ═══════════════════════════════════════════════════════════════

class TestTranslateSetVariable:
    """Tests for SetVariable effect translation."""

    def test_set_var_to_const(self, amd64_translator):
        """SetVariable(va, 'rax', Const(42)) → COPY rax = #42"""
        effect = MockSetVariable(0x401000, "rax", MockConst(42, 8))
        ops = amd64_translator.translate_effect(effect)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.COPY
        assert ops[0].output is not None
        assert ops[0].output.reg_name == "rax"
        assert ops[0].inputs[0].space == VarnodeSpace.CONST
        assert ops[0].inputs[0].offset == 42

    def test_set_var_to_var(self, amd64_translator):
        """SetVariable(va, 'rbx', Var('rax')) → COPY rbx = rax"""
        effect = MockSetVariable(0x401000, "rbx", MockVar("rax", 8))
        ops = amd64_translator.translate_effect(effect)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.COPY
        assert ops[0].output.reg_name == "rbx"
        assert ops[0].inputs[0].reg_name == "rax"

    def test_set_var_to_operator(self, amd64_translator):
        """SetVariable(va, 'rax', o_add(rax, 1)) → INT_ADD then COPY"""
        symobj = MockOperator(
            MockVar("rax", 8), MockConst(1, 8),
            width=8, symtype=SYMT_OPER_ADD,
        )
        effect = MockSetVariable(0x401000, "rax", symobj)
        ops = amd64_translator.translate_effect(effect)

        # Should generate: INT_ADD (for the expression) + COPY (for the assignment)
        assert len(ops) == 2
        assert ops[0].opcode == PcodeOpcode.INT_ADD
        assert ops[1].opcode == PcodeOpcode.COPY
        assert ops[1].output.reg_name == "rax"

    def test_set_var_with_eflags(self, amd64_translator):
        """SetVariable for eflags sub-field should work."""
        effect = MockSetVariable(0x401000, "eflags_zf", MockConst(0, 1))
        ops = amd64_translator.translate_effect(effect)
        assert len(ops) == 1
        assert ops[0].output.reg_name == "eflags_zf"


class TestTranslateDebugEffect:
    """Tests for DebugEffect translation."""

    def test_debug_effect_produces_no_ops(self, amd64_translator):
        effect = MockDebugEffect(0x401000, "Unsupported instruction")
        ops = amd64_translator.translate_effect(effect)
        assert len(ops) == 0


class TestTranslateEffectsList:
    """Tests for translating a list of effects."""

    def test_multiple_effects(self, amd64_translator):
        """Translate a sequence of effects representing a simple function."""
        effects = [
            MockSetVariable(0x401000, "rax", MockConst(0, 8)),
            MockSetVariable(0x401003, "rbx", MockConst(1, 8)),
            MockSetVariable(0x401006, "rax",
                MockOperator(MockVar("rax", 8), MockVar("rbx", 8),
                             width=8, symtype=SYMT_OPER_ADD)),
        ]
        ops = amd64_translator.translate_effects(effects)

        # 2 simple copies + 1 INT_ADD + 1 COPY = 4 ops
        assert len(ops) == 4
        assert ops[0].opcode == PcodeOpcode.COPY
        assert ops[1].opcode == PcodeOpcode.COPY
        assert ops[2].opcode == PcodeOpcode.INT_ADD
        assert ops[3].opcode == PcodeOpcode.COPY

    def test_unique_counter_resets(self, amd64_translator):
        """Each call to translate_effects resets the unique counter."""
        effect = MockSetVariable(0x401000, "rax", MockConst(0, 8))
        ops1 = amd64_translator.translate_effects([effect])
        ops2 = amd64_translator.translate_effects([effect])
        # Both should produce equivalent ops with same unique offsets
        assert ops1[0].output == ops2[0].output


# ═══════════════════════════════════════════════════════════════
# PcodeTranslator — Architecture tests
# ═══════════════════════════════════════════════════════════════

class TestTranslatorArch:
    """Tests for architecture-specific behavior."""

    def test_i386_register_mapping(self, i386_translator):
        """i386 translator maps eax to 4-byte register."""
        node = MockVar("eax", 4)
        ops = []
        vn = i386_translator._translate_ast(node, ops, 0x401000)
        assert vn.size == 4
        assert vn.reg_name == "eax"

    def test_amd64_register_mapping(self, amd64_translator):
        """amd64 translator maps rax to 8-byte register."""
        node = MockVar("rax", 8)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)
        assert vn.size == 8
        assert vn.reg_name == "rax"

    def test_unsupported_arch(self):
        with pytest.raises(ValueError, match="Unsupported"):
            PcodeTranslator(arch="arm")

    def test_i386_psize(self, i386_translator):
        assert i386_translator.psize == 4

    def test_amd64_psize(self, amd64_translator):
        assert amd64_translator.psize == 8


# ═══════════════════════════════════════════════════════════════
# Serialization tests
# ═══════════════════════════════════════════════════════════════

class TestSerialization:
    """Tests for JSON serialization of p-code objects."""

    def test_serialize_ops(self, amd64_translator):
        effects = [
            MockSetVariable(0x401000, "rax", MockConst(42, 8)),
            MockSetVariable(0x401003, "rbx",
                MockOperator(MockVar("rax", 8), MockConst(1, 8),
                             width=8, symtype=SYMT_OPER_ADD)),
        ]
        ops = amd64_translator.translate_effects(effects)
        json_str = amd64_translator.serialize_ops(ops)
        assert isinstance(json_str, str)

        ops2 = PcodeTranslator.deserialize_ops(json_str)
        assert len(ops2) == len(ops)
        assert all(o1.opcode == o2.opcode for o1, o2 in zip(ops, ops2))

    def test_pcode_function_json(self):
        pf = PcodeFunction(
            address=0x401000,
            name="test_func",
            ops=[PcodeOp(opcode=PcodeOpcode.RETURN, va=0x401010)],
            arch="amd64",
        )
        s = pf.to_json()
        d = json.loads(s)
        assert d["address"] == 0x401000
        assert d["name"] == "test_func"
        assert len(d["ops"]) == 1

    def test_symbol_info_to_dict(self):
        si = SymbolInfo(name="main", address=0x401000, is_function=True)
        d = si.to_dict()
        assert d["name"] == "main"
        assert d["is_function"] is True

    def test_decompile_request_to_dict(self):
        req = DecompileRequest(address=0x401000, mode="enriched")
        d = req.to_dict()
        assert d["address"] == "0x401000"
        assert d["mode"] == "enriched"

    def test_decompile_result_from_dict(self):
        d = {
            "c_code": "int main() { return 0; }",
            "function_name": "main",
            "success": True,
        }
        result = DecompileResult.from_dict(d)
        assert result.c_code == "int main() { return 0; }"
        assert result.function_name == "main"
        assert result.success is True


# ═══════════════════════════════════════════════════════════════
# SExtend and CNot tests
# ═══════════════════════════════════════════════════════════════

class TestTranslatorSExtend:
    """Tests for sign extension translation."""

    def test_sextend_generates_int_sext(self, amd64_translator):
        node = MockSExtend(MockVar("eax", 4), MockConst(8, 4))
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)

        assert len(ops) == 1
        assert ops[0].opcode == PcodeOpcode.INT_SEXT
        assert ops[0].output.size == 8


class TestTranslatorCNot:
    """Tests for boolean negate translation."""

    def test_cnot_generates_bool_negate(self, amd64_translator):
        inner = MockConstraint(MockVar("eax", 4), MockConst(0, 4),
                               width=4, symtype=SYMT_CON_EQ)
        node = MockCNot(inner)
        ops = []
        vn = amd64_translator._translate_ast(node, ops, 0x401000)

        # Should generate: INT_EQUAL + BOOL_NEGATE
        assert len(ops) == 2
        assert ops[0].opcode == PcodeOpcode.INT_EQUAL
        assert ops[1].opcode == PcodeOpcode.BOOL_NEGATE