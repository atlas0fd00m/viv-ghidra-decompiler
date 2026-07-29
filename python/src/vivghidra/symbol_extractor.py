"""
Symbol and type extraction from the Vivisect workspace.

This module extracts function signatures, parameter types, symbol names,
cross-references, and calling conventions from a VivWorkspace and converts
them into SymbolInfo objects for the Ghidra symbol enrichment path (Mode 1).
"""

from __future__ import annotations

from typing import Any, Optional

from .models import SymbolInfo


class SymbolExtractor:
    """
    Extract symbol and type information from a VivWorkspace.

    Usage:
        extractor = SymbolExtractor(vw)
        symbols = extractor.extract_all()
        func_syms = extractor.extract_for_function(0x401000)
    """

    def __init__(self, vw: Any):
        self.vw = vw
        self.psize = getattr(vw, "psize", 8)

    def extract_for_function(self, fva: int) -> list[SymbolInfo]:
        """
        Extract symbol info relevant to a specific function.

        Returns:
            - The function itself (name, signature, args)
            - Symbols referenced by the function (calls, string refs)
        """
        symbols: list[SymbolInfo] = []

        # The function itself
        func_sym = self._extract_function_symbol(fva)
        if func_sym:
            symbols.append(func_sym)

        # Function arguments
        try:
            args = self.vw.getFunctionArgs(fva)
            for idx, (typename, argname) in enumerate(args):
                symbols.append(SymbolInfo(
                    name=argname or f"arg{idx}",
                    address=fva,  # args don't have their own address
                    type_name=typename,
                    is_function=False,
                ))
        except Exception:
            pass

        # Called functions and referenced symbols
        try:
            for xref in self.vw.getXrefsFrom(fva):
                to_va = xref[2] if len(xref) > 2 else None
                if to_va is not None and self.vw.isFunction(to_va):
                    sym = self._extract_function_symbol(to_va)
                    if sym and sym not in symbols:
                        symbols.append(sym)
        except Exception:
            pass

        return symbols

    def extract_all(self) -> list[SymbolInfo]:
        """
        Extract all symbols from the workspace.

        This can be slow for large workspaces. Prefer extract_for_function
        when you only need symbols for one function.
        """
        symbols: list[SymbolInfo] = []

        try:
            for fva in self.vw.getFunctions():
                sym = self._extract_function_symbol(fva)
                if sym:
                    symbols.append(sym)
        except Exception:
            pass

        return symbols

    def _extract_function_symbol(self, fva: int) -> Optional[SymbolInfo]:
        """Extract a SymbolInfo for a single function."""
        try:
            name = self.vw.getName(fva) or f"sub_{fva:x}"

            # Try to get the function API info
            api = None
            try:
                api = self.vw.getFunctionApi(fva)
            except Exception:
                pass

            ret_type = ""
            ret_name = ""
            call_conv = ""
            func_name = name
            call_args: list[str] = []

            if api:
                # api is (rettype, retname, callconv, funcname, callargs)
                ret_type = api[0] if len(api) > 0 else ""
                call_conv = api[2] if len(api) > 2 else ""
                func_name = api[3] if len(api) > 3 else name
                if len(api) > 4:
                    call_args = [str(a) for a in api[4]]

            # Determine if this is an import
            is_import = False
            try:
                loc = self.vw.getLocation(fva)
                if loc is not None:
                    # LOC_IMPORT check — L_TINFO is at index 3
                    is_import = (loc[3] == 2)  # LOC_IMPORT = 2 in vivisect.const
            except Exception:
                pass

            return SymbolInfo(
                name=func_name,
                address=fva,
                type_name=ret_type,
                size=self.psize,
                is_function=True,
                is_import=is_import,
                param_types=call_args,
                return_type=ret_type,
            )
        except Exception:
            return None

    def extract_function_signature(self, fva: int) -> dict:
        """
        Extract a function signature as a dict for Ghidra consumption.

        Returns:
            {
                "name": str,
                "address": int,
                "return_type": str,
                "calling_convention": str,
                "params": [{"name": str, "type": str}, ...],
            }
        """
        try:
            name = self.vw.getName(fva) or f"sub_{fva:x}"
            api = self.vw.getFunctionApi(fva)

            ret_type = api[0] if len(api) > 0 else "void"
            call_conv = api[2] if len(api) > 2 else "cdecl"
            func_name = api[3] if len(api) > 3 else name

            params = []
            try:
                args = self.vw.getFunctionArgs(fva)
                for typename, argname in args:
                    params.append({"name": argname, "type": typename})
            except Exception:
                pass

            return {
                "name": func_name,
                "address": fva,
                "return_type": ret_type,
                "calling_convention": call_conv,
                "params": params,
            }
        except Exception:
            return {
                "name": f"sub_{fva:x}",
                "address": fva,
                "return_type": "void",
                "calling_convention": "cdecl",
                "params": [],
            }