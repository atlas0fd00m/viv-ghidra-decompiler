# Vivisect–Ghidra Symbolik Decompiler Bridge

A Vivisect extension that translates symbolik effects to Ghidra p-code,
interfaces with a background Ghidra process via JSON-RPC over TCP,
and displays decompiled C pseudocode in a dock widget.

## Quick Start

### Python Extension (Vivisect side)

```bash
cd python/
pip install -e ".[test]"
pytest tests/ -v
```

### Install as Vivisect Extension

```bash
# Copy or symlink the src/vivghidra directory to your Vivisect plugins path
export VIV_EXT_PATH=~/.viv/plugins
mkdir -p "$VIV_EXT_PATH"
cp -r src/vivghidra "$VIV_EXT_PATH/"
```

### Start Ghidra Backend

```bash
# Set Ghidra install directory
export GHIDRA_INSTALL_DIR=/opt/ghidra

# Start Ghidra headless with the bridge plugin
./scripts/start_ghidra_headless.sh /path/to/binary
```

### Use in Vivisect

1. Load the same binary in Vivisect
2. Run analysis
3. Right-click a function → "Ghidra Decompile" or "View P-Code"
4. Or use menu: Ghidra → Decompile Function (Ctrl+Shift+D)

## Architecture

```
Vivisect (GUI)                        Ghidra (Headless Background)
┌──────────────────────┐              ┌──────────────────────────┐
│ 1. Load binary       │              │ 1. Load same binary      │
│ 2. Run analysis      │              │ 2. TCP server on :13100  │
│ 3. Right-click →     │   JSON-RPC   │ 3. Receive decompile req │
│    "Decompile"       │ ──────────→  │ 4. Apply Vivisect symbols│
│ 4. Symbolik effects  │   over TCP   │ 5. DecompInterface       │
│    → p-code          │ ←──────────  │    .decompileFunction()  │
│ 5. Display C code    │              │ 6. Return C pseudocode   │
│    in dock widget    │              │                          │
└──────────────────────┘              └──────────────────────────┘
```

### Two-Mode Strategy

**Mode 1 — Symbol-Enriched Decompilation (primary):**
Both tools load the same binary. Vivisect's symbolik analysis produces
better symbol names, function signatures, and parameter types than
Ghidra's auto-analysis. These are sent to Ghidra and applied to the
Program before decompilation.

**Mode 2 — P-Code Injection (experimental):**
The p-code translator converts symbolik effects → Ghidra p-code ops.
P-code is injected at function addresses using Ghidra's p-code override
API. Falls back to Mode 1 if injection fails.

The p-code translator is built regardless — it's the core intellectual
contribution and works standalone for export/comparison.

## Project Structure

```
vivisect-ghidra-bridge/
├── python/                   # Vivisect extension (pip-installable)
│   ├── src/vivghidra/
│   │   ├── __init__.py
│   │   ├── models.py         # P-code data models (Varnode, PcodeOp, etc.)
│   │   ├── pcode_translator.py  # Symbolik effects → p-code translation
│   │   ├── symbol_extractor.py  # Extract symbols from VivWorkspace
│   │   ├── ghidra_client.py     # JSON-RPC TCP client
│   │   ├── extension.py         # vivExtension entry point
│   │   ├── decompiler_widget.py # Qt dock widget for C code
│   │   ├── pcode_viewer.py      # P-code inspection widget
│   │   └── config.py            # Environment-based configuration
│   ├── tests/
│   │   ├── conftest.py          # Mock fixtures (no Vivisect needed)
│   │   ├── test_pcode_translator.py  # 84 unit tests
│   │   ├── test_ghidra_client.py
│   │   └── test_symbol_extractor.py
│   └── pyproject.toml
├── java/                     # Ghidra plugin (Phase 2)
├── docs/
│   ├── plan.md               # Full architecture plan
│   └── pcode-mapping.md      # Symbolik → p-code reference
├── scripts/
│   ├── start_ghidra_headless.sh
│   └── install_extension.sh
├── README.md
└── run_tests.sh
```

## Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `VIVGHIDRA_HOST` | `localhost` | Ghidra server hostname |
| `VIVGHIDRA_PORT` | `13100` | Ghidra server port |
| `VIVGHIDRA_TIMEOUT` | `30` | Request timeout (seconds) |
| `GHIDRA_INSTALL_DIR` | — | Path to Ghidra installation |
| `VIV_EXT_PATH` | `~/.viv/plugins` | Vivisect extensions directory |

## Headless API

```python
from vivghidra.extension import decompile_function_headless, translate_pcode_headless

# Translate symbolik effects to p-code (no Ghidra needed)
pcode_func = translate_pcode_headless(vw, 0x401000)
print(f"{len(pcode_func.ops)} p-code ops generated")

# Decompile via Ghidra backend
c_code = decompile_function_headless(vw, 0x401000)
print(c_code)
```

## Testing

```bash
cd python/
pytest tests/ -v
# 84 tests, all passing
```

Tests use mock objects that mimic the Vivisect symbolik API — no Vivisect
installation required. The mock TCP server for GhidraClient tests also
eliminates the need for a running Ghidra instance.

## Architecture Scope

Vivisect symboliks only support **i386** and **amd64**. The p-code translator
targets amd64 first (most common), i386 second. ARM/MIPS/etc. would require
extending Vivisect's symbolik translators — out of scope for v1.

## License

Proprietary — UberNethers / atlas0fd00m