"""
Unit tests for the SymbolExtractor.

Uses a MockVivWorkspace to test symbol/type extraction
without requiring Vivisect to be installed.
"""

import pytest

from vivghidra.symbol_extractor import SymbolExtractor
from vivghidra.models import SymbolInfo


class TestSymbolExtractor:
    """Tests for symbol extraction from a VivWorkspace."""

    def test_extract_for_function(self, mock_vw):
        extractor = SymbolExtractor(mock_vw)
        symbols = extractor.extract_for_function(0x401000)

        # Should return at least the function itself and the called printf
        assert len(symbols) >= 1
        assert any(s.name == "main" for s in symbols)

    def test_extract_import_function(self, mock_vw):
        extractor = SymbolExtractor(mock_vw)
        symbols = extractor.extract_for_function(0x401000)

        # printf is an import called from main
        printf_syms = [s for s in symbols if s.name == "printf"]
        assert len(printf_syms) == 1
        assert printf_syms[0].is_function
        assert printf_syms[0].is_import

    def test_extract_all(self, mock_vw):
        extractor = SymbolExtractor(mock_vw)
        symbols = extractor.extract_all()

        # Should find both functions
        names = {s.name for s in symbols}
        assert "main" in names
        assert "printf" in names

    def test_function_signature(self, mock_vw):
        extractor = SymbolExtractor(mock_vw)
        sig = extractor.extract_function_signature(0x401000)

        assert sig["name"] == "main"
        assert sig["address"] == 0x401000
        assert "return_type" in sig
        assert "calling_convention" in sig
        assert isinstance(sig["params"], list)
        assert len(sig["params"]) == 2  # argc, argv

    def test_function_signature_unknown_function(self, mock_vw):
        extractor = SymbolExtractor(mock_vw)
        sig = extractor.extract_function_signature(0xDEADBEEF)

        # Should return a default signature
        assert "name" in sig
        assert sig["address"] == 0xDEADBEEF

    def test_symbol_info_is_function_flag(self, mock_vw):
        extractor = SymbolExtractor(mock_vw)
        symbols = extractor.extract_all()

        for s in symbols:
            assert s.is_function is True

    def test_extract_for_function_with_no_xrefs(self, mock_vw):
        """Function with no outgoing xrefs still returns its own symbol."""
        extractor = SymbolExtractor(mock_vw)
        symbols = extractor.extract_for_function(0x401200)  # printf

        # Should at least return the function itself
        assert len(symbols) >= 1
        assert symbols[0].name == "printf"