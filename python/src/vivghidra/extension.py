"""
Vivisect extension entry point.

This module implements the vivExtension() function that Vivisect calls
when loading extensions. It wires together the p-code translator,
GhidraClient, symbol extractor, and Qt UI widgets.

UI Integration:
- Context menu: right-click in function → "Ghidra Decompile" / "View P-Code"
- Menu item: &Ghidra.&Decompile Function (Ctrl+Shift+D)
- Dock widget: DecompilerWidget — displays C pseudocode
- P-code viewer: PcodeViewerWidget — displays translated p-code for debugging
"""

from __future__ import annotations

import logging
from typing import Any, Optional

from .config import Config
from .ghidra_client import GhidraClient, GhidraConnectionError
from .pcode_translator import PcodeTranslator
from .symbol_extractor import SymbolExtractor
from .models import DecompileRequest, PcodeFunction

logger = logging.getLogger(__name__)

# Global state — set in vivExtension()
_config: Optional[Config] = None
_client: Optional[GhidraClient] = None
_translator: Optional[PcodeTranslator] = None
_extractor: Optional[SymbolExtractor] = None
_decompiler_widget: Optional[Any] = None
_pcode_widget: Optional[Any] = None


def _decompile_function(vw: Any, fva: int) -> None:
    """
    Decompile a function using the Ghidra backend.

    1. Extract symbols from Vivisect workspace
    2. Translate symbolik effects to p-code (if Mode 2)
    3. Send decompile request to Ghidra
    4. Display result in the dock widget
    """
    global _client, _translator, _extractor, _decompiler_widget

    if _client is None or not _client.connected:
        logger.error("Ghidra client not connected")
        if _decompiler_widget:
            _decompiler_widget.set_error("Not connected to Ghidra server")
        return

    try:
        # Get function name
        func_name = vw.getName(fva) or f"sub_{fva:x}"

        # Extract symbols for enrichment (Mode 1)
        symbols = []
        pcode_ops = []
        if _extractor:
            sym_infos = _extractor.extract_for_function(fva)
            symbols = [s.to_dict() for s in sym_infos]

        # Translate symbolik effects to p-code (Mode 2 — optional)
        if _translator:
            try:
                from vivisect.symboliks.analysis import getSymbolikAnalysisContext
                ctx = getSymbolikAnalysisContext(vw, consolve=False)
                if ctx is not None:
                    pf = _translator.translate_function(fva, ctx, name=func_name)
                    pcode_ops = pf.ops
            except Exception as e:
                logger.debug(f"Symbolik translation skipped: {e}")

        # Build and send request
        req = DecompileRequest(
            address=fva,
            mode="enriched" if symbols else "standard",
            symbols=[],  # populated from SymbolInfo objects if needed
            pcode=pcode_ops,
        )

        # Update p-code viewer if present
        if _pcode_widget and pcode_ops:
            _pcode_widget.set_pcode(pcode_ops, func_name)

        # Send to Ghidra
        result = _client.decompile_function(req)

        # Display in widget
        if _decompiler_widget:
            if result.success:
                _decompiler_widget.set_code(result.c_code, func_name)
            else:
                _decompiler_widget.set_error(result.error or "Decompilation failed")

    except GhidraConnectionError as e:
        logger.error(f"Ghidra connection error: {e}")
        if _decompiler_widget:
            _decompiler_widget.set_error(str(e))
    except Exception as e:
        logger.error(f"Decompilation error: {e}")
        if _decompiler_widget:
            _decompiler_widget.set_error(str(e))


def _view_pcode(vw: Any, fva: int) -> None:
    """
    Translate a function's symbolik effects to p-code and display
    in the p-code viewer widget (no Ghidra connection needed).
    """
    global _translator, _pcode_widget

    if _translator is None:
        _translator = PcodeTranslator(arch=vw.getMeta("Architecture", "amd64"))

    try:
        func_name = vw.getName(fva) or f"sub_{fva:x}"

        from vivisect.symboliks.analysis import getSymbolikAnalysisContext
        ctx = getSymbolikAnalysisContext(vw, consolve=False)
        if ctx is None:
            if _pcode_widget:
                _pcode_widget.set_error("Symbolik analysis not available for this architecture")
            return

        pf = _translator.translate_function(fva, ctx, name=func_name)

        if _pcode_widget:
            _pcode_widget.set_pcode(pf.ops, func_name)

    except Exception as e:
        logger.error(f"P-code translation error: {e}")
        if _pcode_widget:
            _pcode_widget.set_error(str(e))


def _ctx_menu_hook(vw: Any, va: int, expr: Any, menu: Any, parent: Any, nav: Any, tag=None) -> None:
    """
    Context menu hook — called when the user right-clicks in the Vivisect UI.

    Adds "Ghidra Decompile" and "View P-Code" menu items when right-clicking
    on a function.
    """
    try:
        fva = vw.getFunction(va)
        if fva is None:
            return

        # Try to import ACT (Action Callback Thing) from vqt
        try:
            from vqt.common import ACT
            menu.addAction('Ghidra Decompile', ACT(_decompile_function, vw, fva))
            menu.addAction('View P-Code', ACT(_view_pcode, vw, fva))
        except ImportError:
            # Fallback — just log
            logger.debug(f"Context menu: would decompile {fva:#x}")
    except Exception as e:
        logger.debug(f"Context menu hook error: {e}")


def vivExtension(vw: Any, vwgui: Any) -> None:
    """
    Vivisect extension entry point.

    Called by Vivisect when the extension is loaded. Sets up:
    1. Configuration from environment variables
    2. GhidraClient connection (best-effort — doesn't fail if Ghidra is offline)
    3. PcodeTranslator for the workspace's architecture
    4. SymbolExtractor for the workspace
    5. Context menu hooks
    6. Menu items
    7. Dock widgets (hidden initially)

    Args:
        vw: VivWorkspace instance
        vwgui: VQVivMainWindow instance (the Qt GUI)
    """
    global _config, _client, _translator, _extractor, _decompiler_widget, _pcode_widget

    logger.info("Vivisect-Ghidra Bridge extension loading...")

    # 1. Load config
    _config = Config()
    arch = vw.getMeta("Architecture") or "amd64"
    if arch not in ("amd64", "i386"):
        arch = "amd64"  # fallback
    _config.arch = arch

    # 2. Create translator
    _translator = PcodeTranslator(arch=arch)
    logger.info(f"  PcodeTranslator: arch={arch}")

    # 3. Create symbol extractor
    _extractor = SymbolExtractor(vw)

    # 4. Try to connect to Ghidra (best-effort)
    _client = GhidraClient(_config)
    try:
        _client.connect()
        status = _client.ping()
        logger.info(f"  Connected to Ghidra: {status}")
        vw.vprint(f"[vivghidra] Connected to Ghidra at {_config.host}:{_config.port}")
    except GhidraConnectionError as e:
        logger.warning(f"  Could not connect to Ghidra: {e}")
        vw.vprint(f"[vivghidra] Warning: Ghidra server not available at {_config.host}:{_config.port}")
        vw.vprint(f"[vivghidra] P-code translation will work, but decompilation requires the server.")

    # 5. Create UI widgets (Qt — best effort, may not be available in headless mode)
    try:
        from .decompiler_widget import DecompilerWidget
        from .pcode_viewer import PcodeViewerWidget

        _decompiler_widget = DecompilerWidget(vw, vwgui)
        _pcode_widget = PcodeViewerWidget(vw, vwgui)

        # Register dock widgets
        vwgui.vqDockWidget(_decompiler_widget, floating=True)
        vwgui.vqDockWidget(_pcode_widget, floating=True)

    except ImportError:
        logger.info("  Qt widgets not available (headless mode)")
    except Exception as e:
        logger.warning(f"  Could not create UI widgets: {e}")

    # 6. Register context menu hook
    try:
        vw.addCtxMenuHook('vivghidra', _ctx_menu_hook)
    except Exception as e:
        logger.warning(f"  Could not register context menu hook: {e}")

    # 7. Add menu items
    try:
        def _menu_decompile():
            # Get current function from the GUI's current VA
            cur_va = vwgui.vqGetCursorVa() if hasattr(vwgui, 'vqGetCursorVa') else None
            if cur_va is not None:
                fva = vw.getFunction(cur_va)
                if fva is not None:
                    _decompile_function(vw, fva)

        def _menu_view_pcode():
            cur_va = vwgui.vqGetCursorVa() if hasattr(vwgui, 'vqGetCursorVa') else None
            if cur_va is not None:
                fva = vw.getFunction(cur_va)
                if fva is not None:
                    _view_pcode(vw, fva)

        vwgui.vqAddMenuField('&Ghidra.&Decompile Function', _menu_decompile, args=())
        vwgui.vqAddMenuField('&Ghidra.&View P-Code', _menu_view_pcode, args=())
    except Exception as e:
        logger.warning(f"  Could not add menu items: {e}")

    # 8. Add hotkey
    try:
        vwgui.addHotKey('ctrl+shift+d', 'vivghidra:decompile')
        vwgui.addHotKeyTarget('vivghidra:decompile', _menu_decompile)
    except Exception:
        pass

    logger.info("Vivisect-Ghidra Bridge extension loaded.")


# ─── Headless API ───
# These functions allow using the bridge from scripts without the Qt GUI.

def decompile_function_headless(vw: Any, fva: int, config: Optional[Config] = None) -> str:
    """
    Decompile a function without the GUI.

    Args:
        vw: VivWorkspace instance
        fva: function virtual address
        config: optional Config override

    Returns:
        C pseudocode string
    """
    cfg = config or Config()
    arch = vw.getMeta("Architecture") or "amd64"
    if arch not in ("amd64", "i386"):
        arch = "amd64"

    translator = PcodeTranslator(arch=arch)
    extractor = SymbolExtractor(vw)

    # Extract symbols
    sym_infos = extractor.extract_for_function(fva)
    symbols = [s.to_dict() for s in sym_infos]

    # Translate p-code (best effort)
    pcode_ops = []
    try:
        from vivisect.symboliks.analysis import getSymbolikAnalysisContext
        ctx = getSymbolikAnalysisContext(vw, consolve=False)
        if ctx is not None:
            func_name = vw.getName(fva) or f"sub_{fva:x}"
            pf = translator.translate_function(fva, ctx, name=func_name)
            pcode_ops = pf.ops
    except Exception:
        pass

    # Send to Ghidra
    with GhidraClient(cfg) as client:
        req = DecompileRequest(
            address=fva,
            mode="enriched" if symbols else "standard",
            pcode=pcode_ops,
        )
        result = client.decompile_function(req)

    if result.success:
        return result.c_code
    raise GhidraConnectionError(result.error or "Decompilation failed")


def translate_pcode_headless(vw: Any, fva: int) -> PcodeFunction:
    """
    Translate a function's symbolik effects to p-code without the GUI.

    Args:
        vw: VivWorkspace instance
        fva: function virtual address

    Returns:
        PcodeFunction with all translated ops
    """
    arch = vw.getMeta("Architecture") or "amd64"
    if arch not in ("amd64", "i386"):
        arch = "amd64"

    translator = PcodeTranslator(arch=arch)
    func_name = vw.getName(fva) or f"sub_{fva:x}"

    from vivisect.symboliks.analysis import getSymbolikAnalysisContext
    ctx = getSymbolikAnalysisContext(vw, consolve=False)
    if ctx is None:
        raise ValueError(f"Symbolik analysis not available for architecture: {arch}")

    return translator.translate_function(fva, ctx, name=func_name)