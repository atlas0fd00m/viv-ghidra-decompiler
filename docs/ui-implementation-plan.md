# UI Implementation Plan

**Date:** 2026-07-28
**Goal:** Implement the UI features described in `ui-considerations.md`: syntax highlighting, comments, name changes, function signature editing — with full round-trip to Ghidra.

---

## Architecture

### New RPC Methods (Java + Python)

| Method | Params | Returns | Purpose |
|---|---|---|---|
| `set_comment` | `{address: "0x401156", comment: "..."}` | `{success: bool}` | Store EOL comment at address in Ghidra |
| `rename_symbol` | `{address: "0x401156", name: "new_name", is_function: bool}` | `{success: bool}` | Rename a function or data symbol in Ghidra |
| `set_signature` | `{address: "0x401156", name: str, return_type: str, param_types: [str], calling_conv: str}` | `{success: bool}` | Set full function signature in Ghidra |

### Python Client Changes (`ghidra_client.py`)
- Add `set_comment(address, comment)` → dict
- Add `rename_symbol(address, name, is_function)` → dict
- Add `set_signature(address, name, return_type, param_types, calling_conv)` → dict

### Python Model Changes (`models.py`)
- `CommentRequest` dataclass: address, comment
- `RenameRequest` dataclass: address, name, is_function
- `SignatureRequest` dataclass: address, name, return_type, param_types, calling_conv

### Java Server Changes
- `Protocol.java`: new method name constants + param keys
- `SymbolApplier.java`: `setComment(Address, String)`, `renameSymbol(Address, String, boolean)`, `setSignature(Address, String, String, List<String>, String)`
- `VivGhidraBridgePlugin.java` (or `StartBridgeServer.java`): dispatch new methods

### Python UI Changes

#### `syntax_highlighter.py` (NEW)
- `CSyntaxHighlighter(QSyntaxHighlighter)` — highlights C keywords, types, strings, comments, numbers, function names
- C keyword list: int, void, char, if, else, for, while, return, struct, etc.
- Color scheme: keywords=blue bold, types=purple, strings=green, comments=gray italic, numbers=orange

#### `decompiler_widget.py` (UPDATED)
- Apply `CSyntaxHighlighter` to the code_display QTextEdit
- Add right-click context menu on code_display:
  - "Add Comment" → opens input dialog, calls `set_comment` on Ghidra + `vw.setComment` on Vivisect
  - "Rename Function" → opens rename dialog, calls `rename_symbol` on Ghidra + `vw.setName` on Vivisect
  - "Edit Signature" → opens signature dialog, calls `set_signature` on Ghidra + updates Vivisect API
  - "Copy to Clipboard"
  - "Export as .c File"
- Parse address annotations from Ghidra output (`/* 0x401156 */`) and make them clickable
- Store current function address + name for context menu actions

#### `ui_dialogs.py` (NEW)
- `RenameDialog` — simple text input for new name, shows current name
- `SignatureEditDialog` — fields for return type, calling convention, parameter list (name+type pairs, add/remove rows)
- Both return a dict or None if cancelled

#### `extension.py` (UPDATED)
- Wire up new context menu actions in the decompiler widget
- Pass `vw` and `_client` to widget for round-trip operations
- Add "Rename Function" and "Edit Signature" to the Vivisect context menu

---

## Implementation Order

1. **Write tests first** — unit tests for new RPC methods, models, syntax highlighter, dialogs
2. Implement `models.py` additions (CommentRequest, RenameRequest, SignatureRequest)
3. Implement `ghidra_client.py` additions (set_comment, rename_symbol, set_signature)
4. Implement `syntax_highlighter.py`
5. Implement `ui_dialogs.py` (RenameDialog, SignatureEditDialog)
6. Update `decompiler_widget.py` (context menu, syntax highlighting, address parsing)
7. Update `extension.py` (wire up new actions, pass client+vw to widget)
8. Update Java `Protocol.java` with new method constants
9. Update Java `SymbolApplier.java` with setComment, renameSymbol, setSignature
10. Update `StartBridgeServer.java` to dispatch new methods
11. Update `conftest.py` mock server responses for new methods
12. Run full test suite, fix issues
13. Commit, push, create PR

---

## Test Plan

### Python Unit Tests (new file: `test_ui_features.py`)
- `TestCommentRequest` — serialization, address formatting
- `TestRenameRequest` — serialization, is_function flag
- `TestSignatureRequest` — serialization, param_types list
- `TestGhidraClientComments` — set_comment against mock server
- `TestGhidraClientRename` — rename_symbol against mock server
- `TestGhidraClientSignature` — set_signature against mock server

### Python UI Tests (new file: `test_ui_dialogs.py`)
- `TestRenameDialog` — construction, get_value, cancel returns None
- `TestSignatureEditDialog` — construction, get_signature, add/remove params
- `TestCSyntaxHighlighter` — highlighter constructs without error, basic regex patterns

### Java Tests (update `JsonRpcServerTest.java` or new test)
- Test `set_comment` handler returns success
- Test `rename_symbol` handler returns success
- Test `set_signature` handler returns success

### Mock Server Updates (`conftest.py`)
- Add responses for `set_comment`, `rename_symbol`, `set_signature`