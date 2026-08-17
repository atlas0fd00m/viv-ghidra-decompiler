# UI Considerations — TODO

## How does the plugin display the decompilation in Vivisect?

### Current state
`decompiler_widget.py` provides a `DecompilerWidget` (Qt QWidget) that:
- Shows the function name in a header label
- Displays C pseudocode in a read-only `QTextEdit` with Courier font
- Has a Refresh button
- Shows connection status and decompile time in a status bar
- The widget is registered as a dock widget via `vwgui.vqDockWidget()`
- Triggered by right-click → "Ghidra Decompile" context menu hook

### Needed improvements

1. **Syntax highlighting** — currently plain text. Should highlight:
   - Keywords (int, void, if, else, for, return, while, etc.)
   - Function names (bold or colored)
   - Comments (italic gray)
   - Strings (green)
   - Numbers (orange)
   - Use `QSyntaxHighlighter` subclass

2. **Cross-referencing** — clicking a function name or variable in the C code should:
   - Navigate to that function's disassembly in Vivisect
   - Or navigate to the variable's definition
   - Requires parsing the C code output and mapping names to addresses

3. **P-code side panel** — the `PcodeViewerWidget` exists but needs:
   - Synchronized scrolling with the decompiler view
   - Click a p-code op → highlight the corresponding C code line
   - Right-click a p-code op → "View in disassembly"

4. **Address annotations** — the C code from Ghidra contains addresses in comments:
   ```c
   /* 0x401156 */
   int simple_add(int a, int b) { ... }
   ```
   These should be clickable to navigate to that address in Vivisect's disassembly view.

5. **Search/filter** — for large functions, add a search bar to find text in the decompiled output.

6. **Copy to clipboard** — button to copy the C code.

7. **Export** — save decompiled output to a .c file.

## How can comments be added?

### From the decompilation view
- Right-click a line in the decompiled C code → "Add Comment"
- Comment is stored in Vivisect's comment system at the address corresponding to that line
- The comment should also be sent to Ghidra so it appears in Ghidra's decompilation

### Implementation approach
1. Map C code lines to addresses (using Ghidra's line-to-address mapping if available, or by parsing address annotations in comments)
2. Use `vw.setComment(va, comment)` to store in Vivisect
3. Optionally send to Ghidra via a new JSON-RPC method `set_comment` that calls `program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, comment)`

### Comment types to support
- End-of-line comments (most common)
- Function comments (shown at function entry)
- Pre-line comments (shown before the instruction)
- Post-line comments (shown after the instruction)

### API needed
```
Python (vivghidra extension):
  vw.setComment(va, comment)  # already exists in Vivisect

Java (Ghidra plugin):
  set_comment method:
    params: {address: "0x401156", comment: "this is a comment", type: "eol|pre|post|function"}
    → program.getListing().setComment(addr, CodeUnit.EOL_COMMENT, comment)
```

## How can names be changed?

### From the decompilation view
- Right-click a variable, function name, or label → "Rename"
- Prompt for new name
- Apply to both Vivisect and Ghidra

### Implementation approach
1. **In Vivisect**: `vw.setName(va, newname)` — updates the Vivisect workspace
2. **In Ghidra**: Send via `apply_symbols` method (already implemented) with the new name
3. **Re-decompile**: After rename, automatically re-decompile to show updated names in C code
4. **Sync direction**: Vivisect is the source of truth — names changed in Vivisect are pushed to Ghidra

### Variable renaming (local variables)
- Ghidra's decompiler uses auto-generated names (param_1, local_10, uVar1, etc.)
- To rename: use Ghidra's `HighFunction` API to map decompiler variables to storage locations, then apply via `function.replaceParameters()` or `setLocalVariable()`
- This is more complex — requires mapping C variable names to Ghidra's varnode storage
- Phase 1: Just function and global symbol renaming (already works)
- Phase 2: Local variable renaming via Ghidra's `HighSymbol` API

### API needed
```
Python (vivghidra extension):
  vw.setName(va, newname)  # already exists
  # Then send to Ghidra:
  client.apply_symbols([{"name": newname, "address": f"0x{va:x}", "is_function": True}])

Java (Ghidra plugin):
  # Already implemented in SymbolApplier / StartBridgeServer
  # Could add a dedicated rename method:
  rename_symbol:
    params: {address: "0x401156", old_name: "...", new_name: "...", is_function: true}
    → function.setName(new_name, SourceType.USER_DEFINED)
```

## How can function signatures be adjusted?

### From the decompilation view
- Right-click a function → "Edit Signature"
- Dialog showing: return type, calling convention, parameter list (name + type for each)
- Apply changes to both Vivisect and Ghidra

### Implementation approach
1. **In Vivisect**: 
   - `vw.setFunctionApi(fva, (rettype, retname, callconv, funcname, callargs))` 
   - `vw.setFunctionArgs(fva, [(typename, argname), ...])`
2. **In Ghidra**:
   - Set return type: `function.setReturnType(retType, SourceType.USER_DEFINED)`
   - Set parameters: `function.replaceParameters(params, DYNAMIC_STORAGE_FORMAL_PARAMS, true, SourceType.USER_DEFINED)`
   - Both already implemented in `SymbolApplier.java`
3. **Re-decompile** to show the updated signature

### Proven to work
The call_chain test demonstrated this: applying `return_type: int` + `param_types: [int, int]` to Ghidra fixed the decompilation from `void call_chain(undefined4, undefined4)` to `int call_chain(int param0, int param1)`.

### UI mockup
```
┌─────────────────────────────────────────────────┐
│ Edit Function Signature: call_chain             │
├─────────────────────────────────────────────────┤
│ Return type:  [int        ▼]                    │
│ Calling conv: [cdecl      ▼]                    │
│                                                  │
│ Parameters:                                      │
│  #0  [int     ▼]  [a     ]  ← param name        │
│  #1  [int     ▼]  [b     ]  ← param name        │
│  [+ Add Parameter] [- Remove] [↑↓ Reorder]      │
│                                                  │
│              [Apply]  [Cancel]                   │
└─────────────────────────────────────────────────┘
```

### API needed
```
Python (vivghidra extension):
  # Extract current signature
  sig = extractor.extract_function_signature(fva)
  # Apply new signature to Vivisect
  vw.setFunctionApi(fva, (ret_type, ret_name, callconv, funcname, callargs))
  # Apply to Ghidra
  client.apply_symbols([{
      "name": funcname, "address": f"0x{fva:x}",
      "is_function": True, "return_type": ret_type,
      "param_types": [p["type"] for p in new_params]
  }])
  # Re-decompile
  result = client.decompile_function(DecompileRequest(address=fva, mode="enriched"))
  widget.set_code(result.c_code, funcname)
```

## Implementation Priority

| Feature | Priority | Complexity | Status |
|---|---|---|---|
| Syntax highlighting | Medium | Low | Not started |
| Function name renaming | High | Low | Backend works (apply_symbols) |
| Function signature editing | High | Medium | Backend works, needs UI dialog |
| Comments (Vivisect → Ghidra) | Medium | Medium | Not started |
| Local variable renaming | Low | High | Not started (needs HighSymbol API) |
| Address cross-referencing | Medium | Medium | Not started |
| P-code/C code sync | Low | High | Not started |
| Copy/export | Low | Low | Not started |