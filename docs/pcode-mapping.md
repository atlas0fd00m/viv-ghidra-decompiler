# Symbolik → P-Code Mapping Reference

This document is the complete reference for how Vivisect symbolik effects
and AST nodes map to Ghidra p-code operations.

## 1. Effect → P-Code Mapping

| Symbolik Effect | Ghidra P-Code Op | Inputs | Output | Notes |
|---|---|---|---|---|
| `SetVariable(va, name, Const(v))` | `COPY` | `[const_v]` | `dest_reg` | Simple constant assignment |
| `SetVariable(va, name, Var(v))` | `COPY` | `[src_reg]` | `dest_reg` | Register-to-register copy |
| `SetVariable(va, name, o_add(v1,v2))` | `INT_ADD` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | Two ops: compute then assign |
| `SetVariable(va, name, o_sub(v1,v2))` | `INT_SUB` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | |
| `SetVariable(va, name, o_mul(v1,v2))` | `INT_MULT` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | |
| `SetVariable(va, name, o_div(v1,v2))` | `INT_DIV` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | Unsigned division |
| `SetVariable(va, name, o_mod(v1,v2))` | `INT_REM` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | Unsigned remainder |
| `SetVariable(va, name, o_and(v1,v2))` | `INT_AND` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | |
| `SetVariable(va, name, o_or(v1,v2))` | `INT_OR` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | |
| `SetVariable(va, name, o_xor(v1,v2))` | `INT_XOR` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | |
| `SetVariable(va, name, o_lshift(v1,v2))` | `INT_LEFT` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | |
| `SetVariable(va, name, o_rshift(v1,v2))` | `INT_RIGHT` + `COPY` | `[v1, v2]` | `unique` → `dest_reg` | Logical right shift |
| `SetVariable(va, name, o_sextend(v,t)` | `INT_SEXT` + `COPY` | `[v]` | `unique` → `dest_reg` | Sign extension |
| `ReadMemory(va, addr, size)` | `LOAD` | `[space_id, addr]` | `unique` | space_id is const 0 (ram) |
| `WriteMemory(va, addr, size, val)` | `STORE` | `[space_id, addr, val]` | none | space_id is const 0 (ram) |
| `CallFunction(va, func, args)` | `CALL` | `[func_addr, *args]` | `unique` (optional) | |
| `ConstrainPath(va, target, cons)` | `CBRANCH` | `[target, condition]` | none | Condition is a comparison op |
| `DebugEffect(va, msg)` | *(none)* | — | — | Unsupported instruction, skipped |

## 2. Operator → P-Code Mapping

| Symbolik Operator | symtype | Ghidra P-Code | Operands |
|---|---|---|---|
| `o_add(v1, v2)` | `SYMT_OPER_ADD` | `INT_ADD` | `(v1, v2)` |
| `o_sub(v1, v2)` | `SYMT_OPER_SUB` | `INT_SUB` | `(v1, v2)` |
| `o_mul(v1, v2)` | `SYMT_OPER_MUL` | `INT_MULT` | `(v1, v2)` |
| `o_div(v1, v2)` | `SYMT_OPER_DIV` | `INT_DIV` | `(v1, v2)` |
| `o_mod(v1, v2)` | `SYMT_OPER_MOD` | `INT_REM` | `(v1, v2)` |
| `o_and(v1, v2)` | `SYMT_OPER_AND` | `INT_AND` | `(v1, v2)` |
| `o_or(v1, v2)` | `SYMT_OPER_OR` | `INT_OR` | `(v1, v2)` |
| `o_xor(v1, v2)` | `SYMT_OPER_XOR` | `INT_XOR` | `(v1, v2)` |
| `o_lshift(v1, v2)` | `SYMT_OPER_LSHIFT` | `INT_LEFT` | `(v1, v2)` |
| `o_rshift(v1, v2)` | `SYMT_OPER_RSHIFT` | `INT_RIGHT` | `(v1, v2)` |
| `o_pow(v1, v2)` | `SYMT_OPER_POW` | `INT_MULT` | `(v1, v2)` | No direct p-code equivalent |
| `o_sextend(v, tgtsz)` | `SYMT_SEXT` | `INT_SEXT` | `(v)` | |

## 3. Constraint → P-Code Mapping

| Symbolik Constraint | symtype | Ghidra P-Code | Operand Order | Notes |
|---|---|---|---|---|
| `eq(v1, v2)` | `SYMT_CON_EQ` | `INT_EQUAL` | `(v1, v2)` | |
| `ne(v1, v2)` | `SYMT_CON_NE` | `INT_NOTEQUAL` | `(v1, v2)` | |
| `gt(v1, v2)` | `SYMT_CON_GT` | `INT_SLESS` | `(v2, v1)` | **swapped**: v1>v2 ⟺ v2<v1 |
| `ge(v1, v2)` | `SYMT_CON_GE` | `INT_SLESSEQUAL` | `(v2, v1)` | **swapped**: v1≥v2 ⟺ v2≤v1 |
| `lt(v1, v2)` | `SYMT_CON_LT` | `INT_SLESS` | `(v1, v2)` | |
| `le(v1, v2)` | `SYMT_CON_LE` | `INT_SLESSEQUAL` | `(v1, v2)` | |
| `cnot(v)` | `SYMT_NOT` | `BOOL_NEGATE` | `(v)` | |

**Important**: `gt` and `ge` swap their operands in the p-code output because
Ghidra's p-code uses `INT_SLESS(a, b)` to mean `a < b`, while Vivisect's
`gt(v1, v2)` means `v1 > v2`, which is equivalent to `v2 < v1`.

## 4. Varnode Mapping

### Spaces

| Symbolik Node | Ghidra Space | Offset | reg_name |
|---|---|---|---|
| `Const(value, width)` | `const` | `value` | — |
| `Var("rax", 8)` | `register` | canonical offset | `"rax"` |
| `Var("eax", 4)` | `register` | canonical offset | `"eax"` |
| `Var("eflags_zf", 1)` | `register` | eflags base offset | `"eflags_zf"` |
| `Var("unknown", 4)` | `unique` | hash of name | `"unknown"` |
| `Arg(idx, width)` | `unique` | `0x1000 + idx` | `"arg{idx}"` |
| Intermediate result | `unique` | sequential counter | — |

### AMD64 Register Offsets

| Register | Offset | Size | Sub-registers |
|---|---|---|---|
| RAX | 0 | 8 | EAX(4), AX(2), AL(1), AH(1) |
| RCX | 8 | 8 | ECX(4), CX(2), CL(1), CH(1) |
| RDX | 16 | 8 | EDX(4), DX(2), DL(1), DH(1) |
| RBX | 24 | 8 | EBX(4), BX(2), BL(1), BH(1) |
| RSP | 32 | 8 | ESP(4), SP(2) |
| RBP | 40 | 8 | EBP(4), BP(2) |
| RSI | 48 | 8 | ESI(4), SI(2) |
| RDI | 56 | 8 | EDI(4), DI(2) |
| R8-R15 | 64-120 | 8 | R8D-R15D(4) |
| RIP | 128 | 8 | EIP(4) |
| EFLAGS | 136 | 8 | sub-fields: zf, sf, cf, etc. |

### I386 Register Offsets

| Register | Offset | Size | Sub-registers |
|---|---|---|---|
| EAX | 0 | 4 | AX(2), AL(1), AH(1) |
| ECX | 4 | 4 | CX(2), CL(1), CH(1) |
| EDX | 8 | 4 | DX(2), DL(1), DH(1) |
| EBX | 12 | 4 | BX(2), BL(1), BH(1) |
| ESP | 16 | 4 | SP(2) |
| EBP | 20 | 4 | BP(2) |
| ESI | 24 | 4 | SI(2) |
| EDI | 28 | 4 | DI(2) |
| EIP | 32 | 4 | |
| EFLAGS | 36 | 4 | |

## 5. Translation Examples

### Example 1: `mov rax, 42`

Vivisect symbolik effect:
```
SetVariable(0x401000, "rax", Const(42, 8))
```

Generated p-code:
```
COPY rax:8 = #0x2a:8
```

### Example 2: `add rax, rbx`

Vivisect symbolik effect:
```
SetVariable(0x401003, "rax", o_add(Var("rax", 8), Var("rbx", 8)))
```

Generated p-code:
```
INT_ADD u0:8 = rax:8, rbx:8
COPY    rax:8 = u0:8
```

### Example 3: `cmp eax, 0; jne 0x401050`

Vivisect symbolik effects:
```
SetVariable(0x401006, "eflags_eq", eq(Var("eax", 4), Const(0, 4)))
ConstrainPath(0x401008, Const(0x401050, 4), ne(Var("eax", 4), Const(0, 4)))
```

Generated p-code:
```
INT_EQUAL  u0:1 = eax:4, #0x0:4
INT_NOTEQUAL u1:1 = eax:4, #0x0:4
CBRANCH    #0x401050:4, u1:1
```

### Example 4: `call printf`

Vivisect symbolik effect:
```
CallFunction(0x401020, Const(0x401200, 8), [Var("rdi", 8)])
```

Generated p-code:
```
CALL #0x401200:8, rdi:8
```

### Example 5: `mov [rbp-8], rax` (memory write)

Vivisect symbolik effect:
```
WriteMemory(0x401010, o_sub(Var("rbp", 8), Const(8, 8)), Const(8, 4), Var("rax", 8))
```

Generated p-code:
```
INT_SUB u0:8 = rbp:8, #0x8:8
STORE   #0x0:8, u0:8, rax:8
```