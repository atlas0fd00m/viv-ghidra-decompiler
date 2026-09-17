# Real-World Binary Testing Report

**Date:** 2026-07-28
**Binary:** `/usr/bin/base64` — stripped, x86-64, PIE, 39KB, dynamically linked
**Tools:** Ghidra 12.1.2, Vivisect 1.3.2

## Results

### Ghidra Side ✅
- **138 functions discovered** (18 user functions + 120 library/PLT stubs)
- **All user functions decompiled successfully** — C pseudocode is correct and readable
- `FUN_001038b0` identified as base64 encoding block (bit shift `<< 2 | >> 4` pattern visible)
- `FUN_00103b20` (980 bytes, 121 lines decompiled) — main processing loop with file I/O

### UI Features on Real Binary ✅
- **Rename:** `FUN_001038b0` → `base64_encode_block` — applied, name appears in re-decompiled output
- **Comment:** Set at `0x1038b0` — applied successfully
- **Signature:** Set `void base64_encode_block(int, char *, int)` — applied, re-decompiled output shows new signature

### Vivisect Side ✅ (with caveats)
- **81 functions discovered** (fewer than Ghidra — different analysis heuristics)
- **Symbolik analysis works** — graph created for functions
- PLT analysis throws `InvalidFile` exception (Vivisect bug with PIE GOT parsing, not our code)

### Symbol Enrichment ⚠️ — Address Space Mismatch
**Critical finding:** PIE binaries are loaded at different base addresses by Ghidra and Vivisect:
- Ghidra base: `0x00100000` (function at `0x001023c0`)
- Vivisect base: `0x02000000` (same function at `0x020023c0`)
- Offset within binary is identical (`0x23c0`), but base differs

**Impact:** Symbol enrichment from Vivisect → Ghidra fails because addresses don't match.
The `SymbolExtractor` produces addresses in Vivisect's address space, but `SymbolApplier`
on the Ghidra side expects Ghidra's address space.

**Fix needed:** The extension needs to map Vivisect addresses to Ghidra addresses before
sending symbols. Options:
1. **Subtract Vivisect base, add Ghidra base** — requires knowing both base addresses
2. **Use file offsets** — both tools know the file offset; map to each tool's VA space
3. **Send offset-based addresses** — change the protocol to use offsets instead of VAs

Option 1 is simplest: `ghidra_addr = viv_addr - viv_base + ghidra_base`

### Address Format Bug (Fixed)
Ghidra returns addresses as `001023a0` (no `0x` prefix, leading zeros). The test code
was trying `int(addr)` which fails. Fixed to always use `int(addr, 16)`.

## Test Summary

| Test | Result |
|---|---|
| Connect to Ghidra server | ✅ |
| Ping response | ✅ |
| Program loaded | ✅ |
| Function list (138 functions) | ✅ |
| Decompilation of user functions | ✅ |
| C code quality (readable, correct) | ✅ |
| Rename function via RPC | ✅ |
| Set comment via RPC | ✅ |
| Set signature via RPC | ✅ |
| Name appears in re-decompiled output | ✅ |
| Vivisect loads binary | ✅ |
| Vivisect symbolik analysis | ✅ |
| Symbol extraction | ✅ |
| Symbol enrichment (Vivisect → Ghidra) | ❌ Address space mismatch |
| Address format handling | ⚠️ Fixed in test, needs fix in production code |