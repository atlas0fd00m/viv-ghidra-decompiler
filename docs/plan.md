# Vivisect–Ghidra Symbolik Decompiler Bridge

**Date:** 2026-07-20
**Requested by:** atlas
**Goal:** Design and implement a Vivisect plug-in/extension that uses symboliks to generate Ghidra p-code and interfaces with a background Ghidra process to decompile functions and display them in Vivisect.

---

## Research Findings

### Vivisect Side

**Extensions** are convention-based, not class-based. A module implements a `vivExtension(vw, vwgui)` function, discovered by scanning `VIV_EXT_PATH` (default `~/.viv/plugins/`). UI integration:
- `vwgui.vqAddMenuField('&Menu.&Sub.&Item', callback)` — menu items
- `vwgui.vqDockWidget(widget, floating=True)` — dock panels
- `vw.addCtxMenuHook('name', handler)` — right-click context menu hooks

**Symboliks** (`vivisect/symboliks/`): Vivisect's own symbolic execution engine. Entry point:
```python
from vivisect.symboliks.analysis import getSymbolikAnalysisContext
ctx = getSymbolikAnalysisContext(vw)
graph = ctx.getSymbolikGraph(fva)        # per-codeblock symbolik effects
for emu, effects in ctx.walkSymbolikPaths(fva):
    ret = emu.getFunctionReturn()
```

The symbolik IR has two layers:
1. **Effects** (side-effect IR): `SetVariable`, `ReadMemory`, `WriteMemory`, `CallFunction`, `ConstrainPath`, `DebugEffect`
2. **AST** (value expressions): `Var(name, width)`, `Const(value, width)`, `Mem(symaddr, symsize)`, `Call(funcsym, width, argsyms)`, operators (`o_add`, `o_sub`, `o_mul`, `o_and`, `o_or`, `o_xor`, `o_lshift`, `o_rshift`, etc.), constraints (`eq`, `ne`, `gt`, `lt`, `ge`, `le`)

**Only i386 and amd64 are supported** for symboliks.

**No existing p-code, Ghidra, or decompiler integration whatsoever.** Zero grep hits across the entire codebase. The symbolik IR is fundamentally different from p-code (effect-based with algebraic AST vs. varnode-based SSA-ish three-address ops).

### Ghidra Side

**DecompInterface** is the programmatic decompiler API:
```java
DecompInterface ifc = new DecompInterface();
ifc.setOptions(options);
ifc.openProgram(program);
DecompileResults res = ifc.decompileFunction(func, timeoutSecs, monitor);
String cCode = res.getDecompiledFunction().getC();      // C pseudocode
HighFunction hf = res.getHighFunction();                  // high p-code (SSA)
```

The decompiler always works on a `Program` + `Function` — it does NOT accept raw p-code as input. It internally lifts Sleigh-generated instruction p-code to high p-code during decompilation.

**P-code ops** (~100+): `COPY`, `LOAD`, `STORE`, `INT_ADD`, `INT_SUB`, `INT_MULT`, `INT_DIV`, `INT_AND`, `INT_OR`, `INT_XOR`, `INT_LEFT`, `INT_RIGHT`, `INT_SEXT`, `INT_EQUAL`, `INT_NOTEQUAL`, `INT_LESS`, `BRANCH`, `CBRANCH`, `CALL`, `RETURN`, `PIECE`, `SUBPIECE`, `ZEXT`, `BOOL_NEGATE`, etc.

**JSON-RPC-over-TCP pattern** (documented in our Ghidra plugin skill): newline-delimited JSON, zero Java dependencies, daemon thread server, hex-encoded binary data.

**Headless operation**: `analyzeHeadless` can run Ghidra scripts. A plugin with a TCP server can stay alive as a background process, accepting requests from the Vivisect side.

---

## Architecture

### High-Level Flow

```
┌─────────────────────────────────────────────────┐
│                  Vivisect (GUI)                   │
│                                                   │
│  1. User loads binary, runs analysis             │
│  2. User right-clicks function → "Decompile"     │
│  3. Plugin gets symbolik effects for function    │
│  4. PcodeTranslator converts effects → p-code    │
│  5. GhidraClient sends {addr, pcode, symbols}    │
│     to background Ghidra via JSON-RPC/TCP         │
│  6. Receives C pseudocode back                   │
│  7. Displays in dock widget                      │
└──────────────────┬──────────────────────────────┘
                   │ JSON-RPC over TCP
                   ▼
┌─────────────────────────────────────────────────┐
│              Ghidra (Headless Background)          │
│                                                   │
│  1. Loaded same binary as Program                │
│  2. VivGhidraBridgePlugin runs TCP server        │
│  3. Receives decompile request:                  │
│     - function address                           │
│     - symbolik-derived p-code (optional)         │
│     - symbol/type info from Vivisect             │
│  4. DecompInterface.decompileFunction()          │
│     (uses Ghidra's own p-code from Sleigh,       │
│      augmented with Vivisect symbol info)        │
│  5. Returns C pseudocode + high p-code           │
└─────────────────────────────────────────────────┘
```

### Key Design Decision: Two-Mode P-Code Strategy

The Ghidra decompiler cannot accept raw p-code as direct input — it decompiles `Function` objects within a `Program`. Therefore, we use a two-mode strategy:

**Mode 1 — Symbol-Enriched Decompilation (primary):**
- Both Vivisect and Ghidra load the same binary
- The Vivisect plugin translates symbolik-derived analysis (function signatures, parameter types, symbol names, cross-references, calling conventions) into Ghidra's symbol/type system
- These are sent to Ghidra and applied to the Program before decompilation
- Ghidra decompiles using its own Sleigh p-code + Vivisect's symbol intelligence
- This produces better decompilation than either tool alone

**Mode 2 — P-Code Injection (experimental/advanced):**
- The plugin generates p-code from symbolik effects (the novel translation layer)
- P-code is injected at function addresses using Ghidra's p-code injection API (`PcodeEmulator.inject()` or instruction override)
- This is for cases where Vivisect's analysis disagrees with or improves upon Ghidra's Sleigh translation
- Falls back to Mode 1 if injection fails

The p-code translator (symbolik effects → Ghidra p-code) is implemented regardless — it's the core intellectual contribution and enables both modes plus potential future uses (standalone p-code export, comparison analysis, etc.).

---

## Project Structure

```
vivisect-ghidra-bridge/
├── python/                              # Vivisect extension
│   ├── src/vivghidra/
│   │   ├── __init__.py
│   │   ├── extension.py                 # vivExtension entry point, menu/ctx hooks
│   │   ├── pcode_translator.py          # symbolik effects/AST → Ghidra p-code
│   │   ├── symbol_extractor.py          # extract symbols/types/xrefs from vw
│   │   ├── ghidra_client.py             # JSON-RPC TCP client
│   │   ├── decompiler_widget.py         # Qt dock widget for C code display
│   │   ├── pcode_viewer.py              # p-code inspection widget (debugging)
│   │   └── config.py                    # connection settings, env vars
│   ├── tests/
│   │   ├── test_pcode_translator.py     # unit tests for symbolik→p-code mapping
│   │   ├── test_ghidra_client.py        # client against mock server
│   │   ├── test_symbol_extractor.py     # extraction from test workspace
│   │   └── conftest.py                  # fixtures: mock vw, sample effects
│   └── pyproject.toml
├── java/                                # Ghidra plugin
│   ├── src/main/java/vivghidra/
│   │   ├── VivGhidraBridgePlugin.java   # main plugin (ProgramPlugin)
│   │   ├── JsonRpcServer.java           # TCP JSON-RPC server thread
│   │   ├── DecompilerService.java       # wraps DecompInterface
│   │   ├── SymbolApplier.java           # applies Vivisect symbols/types to Program
│   │   ├── PcodeInjector.java           # injects p-code at addresses (Mode 2)
│   │   ├── JsonUtil.java                # minimal zero-dep JSON parser
│   │   └── Protocol.java                # method names, param schemas
│   ├── src/test/java/vivghidra/
│   │   ├── JsonRpcServerTest.java
│   │   └── JsonUtilTest.java
│   ├── extension.properties
│   ├── Module.manifest
│   ├── build.gradle
│   └── build.sh
├── docs/
│   ├── architecture.md                  # this document, expanded
│   └── pcode-mapping.md                 # symbolik→p-code op reference
├── scripts/
│   ├── start_ghidra_headless.sh         # launch Ghidra with plugin + binary
│   └── install_extension.sh             # copy python ext to ~/.viv/plugins/
├── README.md
└── run_tests.sh
```

---

## Implementation Plan — Phase by Phase

### Phase 1: P-Code Translator (Python, no Ghidra needed)

The core translation layer. Maps Vivisect symbolik effects/AST to Ghidra p-code operations.

**Symbolik Effect → P-Code Mapping:**

| Symbolik Effect | Ghidra P-Code | Notes |
|---|---|---|
| `SetVariable(va, varname, Const(v))` | `COPY unique=N, Const(v)` | Assign constant to varnode |
| `SetVariable(va, varname, Var(v))` | `COPY unique=N, Var(v)` | Register/register copy |
| `SetVariable(va, varname, o_add(v1,v2))` | `INT_ADD unique=N, v1, v2` | Binary op |
| `SetVariable(va, varname, o_sub(v1,v2))` | `INT_SUB unique=N, v1, v2` | |
| `SetVariable(va, varname, o_mul(v1,v2))` | `INT_MULT unique=N, v1, v2` | |
| `SetVariable(va, varname, o_and(v1,v2))` | `INT_AND unique=N, v1, v2` | |
| `SetVariable(va, varname, o_or(v1,v2))` | `INT_OR unique=N, v1, v2` | |
| `SetVariable(va, varname, o_xor(v1,v2))` | `INT_XOR unique=N, v1, v2` | |
| `SetVariable(va, varname, o_lshift(v1,v2))` | `INT_LEFT unique=N, v1, v2` | |
| `SetVariable(va, varname, o_rshift(v1,v2))` | `INT_RIGHT unique=N, v1, v2` | |
| `SetVariable(va, varname, o_sextend(v))` | `INT_SEXT unique=N, v` | Sign extension |
| `ReadMemory(va, addr, size)` | `LOAD unique=N, addr` | Memory read |
| `WriteMemory(va, addr, size, val)` | `STORE addr, val` | Memory write |
| `CallFunction(va, funcsym, args)` | `CALL funcsym, args` | Function call |
| `ConstrainPath(va, addrsym, cons)` | `CBRANCH addrsym, cons` | Conditional branch |
| `i_ret` (return effect) | `RETURN` | Function return |

**Constraint → P-Code Mapping:**

| Symbolik Constraint | Ghidra P-Code |
|---|---|
| `eq(v1, v2)` | `INT_EQUAL v1, v2` |
| `ne(v1, v2)` | `INT_NOTEQUAL v1, v2` |
| `gt(v1, v2)` | `INT_LESS v2, v1` (signed: `INT_SLESS`) |
| `lt(v1, v2)` | `INT_LESS v1, v2` |
| `ge(v1, v2)` | `INT_LESSEQUAL v2, v1` |
| `le(v1, v2)` | `INT_LESSEQUAL v1, v2` |
| `cnot(v)` | `BOOL_NEGATE v` |

**Varnode mapping:** Symbolik `Var(name, width)` → Ghidra varnode with register space (for known registers) or unique space (for temporaries). `Const(value, width)` → constant varnode.

**Deliverables:**
- `pcode_translator.py` — `PcodeTranslator` class with `translate_effects(effects) → list[PcodeOp]` and `translate_function(fva, ctx) → PcodeFunction`
- `PcodeOp` dataclass: `opcode, output_varnode, input_varnodes, va`
- `Varnode` dataclass: `space, offset, size` (spaces: `register`, `unique`, `const`, `ram`)
- Serialization to JSON for TCP transport
- Full unit test suite with mock symbolik effects
- `docs/pcode-mapping.md` — complete reference document

**Tests:** Mock symbolik effects (no Vivisect workspace needed), verify correct p-code op generation, varnode spaces, widths.

### Phase 2: Ghidra Plugin + JSON-RPC Server (Java)

The background Ghidra process that accepts decompilation requests.

**JSON-RPC Protocol:**

```
Methods:
  ping                        → {pong: true, version: "1.0"}
  get_status                  → {program_loaded: bool, program_name: str}
  decompile_function          → {c_code: str, high_pcode: [...]}
    params: {address: "0x401000", mode: "standard|enriched|injected",
             symbols: {...}, pcode: [...]}
  get_pcode                   → {pcode: [...]}
    params: {address: "0x401000"}
  apply_symbols               → {applied: int}
    params: {symbols: [{name, address, type, size}, ...]}
  get_function_list           → {functions: [{name, address, size}, ...]}
  set_decompiler_options      → {success: bool}
    params: {options: {...}}
```

**Deliverables:**
- `VivGhidraBridgePlugin.java` — `ProgramPlugin` that starts TCP server on `programActivated`
- `JsonRpcServer.java` — daemon thread, newline-JSON, one thread per client
- `DecompilerService.java` — wraps `DecompInterface`, handles decompile requests, caches results
- `SymbolApplier.java` — applies Vivisect-derived symbol names, function signatures, data types to Ghidra `Program` before decompilation
- `PcodeInjector.java` — (Mode 2) injects p-code ops at addresses using Ghidra's p-code override
- `JsonUtil.java` — minimal JSON parser (zero dependencies)
- `Protocol.java` — method name constants, param validation
- JUnit tests for JSON parsing and server protocol
- `extension.properties`, `Module.manifest`, `build.gradle`, `build.sh`

### Phase 3: Vivisect Extension (Python, Qt UI)

The user-facing Vivisect plugin that ties everything together.

**UI Integration:**
- Context menu hook: right-click in function → "Ghidra Decompile" / "View P-Code"
- Menu item: `&Ghidra.&Decompile Function` (Ctrl+Shift+D)
- Dock widget: `DecompilerWidget` — syntax-highlighted C code display with:
  - Function name header
  - C pseudocode body (with basic syntax highlighting via QTextEdit)
  - Toggle button: show/hide p-code side panel
  - Status bar: connection status, decompile time
- P-code viewer widget: `PcodeViewerWidget` — tabular p-code display for debugging

**GhidraClient (Python):**
- JSON-RPC TCP client (mirrors the skill's pattern)
- Auto-reconnect, timeout handling
- Methods matching the Java server's protocol
- Connection config via env vars: `VIVGHIDRA_HOST` (default `localhost`), `VIVGHIDRA_PORT` (default `13100`)

**Extension Entry Point:**
```python
def vivExtension(vw, vwgui):
    # 1. Load config
    # 2. Create GhidraClient, test connection
    # 3. Register context menu hook
    # 4. Add menu items
    # 5. Create dock widget (hidden initially)
```

**Deliverables:**
- `extension.py` — entry point, wiring
- `ghidra_client.py` — TCP client
- `decompiler_widget.py` — C code dock widget
- `pcode_viewer.py` — p-code display widget
- `symbol_extractor.py` — extract function args, names, types, xrefs from `vw`
- `config.py` — env var parsing, defaults
- `install_extension.sh` — symlink/copy to `~/.viv/plugins/vivghidra/`
- Tests for client (mock server) and symbol extractor (mock workspace)

### Phase 4: Integration Testing + Polish

**Integration test:**
- Launch Ghidra headless with plugin + test binary
- Launch Vivisect with extension + same binary
- Programmatically trigger decompilation
- Verify C code is returned and displayed

**Test binary:** Use a simple compiled C program (e.g., a function with loops, branches, memory access) as the test fixture for both sides.

**Deliverables:**
- `scripts/start_ghidra_headless.sh` — launch Ghidra with plugin loaded, binary imported, TCP server listening
- `run_tests.sh` — runs Python unit tests, Java unit tests, and integration test
- `README.md` — setup, usage, architecture overview
- `docs/architecture.md` — expanded architecture doc with diagrams

---

## Technical Risks & Mitigations

| Risk | Mitigation |
|---|---|
| P-code injection (Mode 2) may not work with decompiler — decompiler reads Sleigh p-code, not injected | Mode 1 (symbol enrichment) is primary; Mode 2 is experimental. If injection doesn't produce decompilable functions, Mode 2 becomes a p-code export/comparison feature only. |
| Symbolik translator only supports i386/amd64 | Phase 1 targets amd64 first (most common), i386 second. ARM/etc. would require extending Vivisect's symbolik translators — out of scope for v1. |
| Ghidra version differences (11.x vs 12.1) | Plugin targets Ghidra 12.1+ (latest). API changes documented in skill. `build.gradle` uses `GHIDRA_INSTALL_DIR` env var for portability. |
| Binary must be loaded in both tools | The start script handles this: import binary into Ghidra project, analyze, start plugin. User loads same binary in Vivisect. |
| JSON-RPC performance for large functions | P-code is compact (text-based). C code response could be large for big functions but is a single string. Timeout handling in client. |

---

## Build & Test Strategy

- **Python:** `pytest` with mock objects for Vivisect workspace and Ghidra server. No live Ghidra needed for unit tests.
- **Java:** JUnit 5 (standalone, no Gradle required for testing). Mock TCP connections. Skill has the full recipe.
- **Integration:** Shell script that starts Ghidra headless, runs a Python script that connects and decompiles, asserts on the output.
- **Ghidra installation:** Download from GitHub releases to `/opt/ghidra` or `$GHIDRA_INSTALL_DIR`. JDK 21 required.

---

## What I Need From You (atlas)

1. **Review this plan** — especially the two-mode strategy. Is Mode 2 (p-code injection) something you want in v1, or should I focus on Mode 1 (symbol-enriched decompilation) and treat the p-code translator as a standalone export feature?

2. **Ghidra version** — Do you have a specific Ghidra version installed on MATRIX or Fangorn, or should I target the latest (12.1)?

3. **Test binary** — Any preference for the test fixture binary, or should I compile a simple one?

4. **Architecture scope** — The plan targets amd64 only (Vivisect symboliks limitation). Is that acceptable for v1?

5. **Repo location** — Where should I create the project? `~/projects/vivisect-ghidra-bridge/`? Somewhere else?