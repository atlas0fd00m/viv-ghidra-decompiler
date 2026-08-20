"""
Unit tests for UI dialog classes and syntax highlighter.

These tests verify the dialog logic without requiring a real Qt event loop.
We test the data structures and methods, not the visual rendering.
"""

import pytest

# Qt imports — skip all tests if Qt not available
try:
    from PySide6 import QtCore, QtGui, QtWidgets
    QT_AVAILABLE = True
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
        QT_AVAILABLE = True
    except ImportError:
        QT_AVAILABLE = False

pytestmark = pytest.mark.skipif(not QT_AVAILABLE, reason="Qt not available for UI dialog tests")

# Shared QApplication instance for all UI dialog tests
_qapp = None

def _get_qapp():
    global _qapp
    if _qapp is None and QT_AVAILABLE:
        _qapp = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    return _qapp


class TestRenameDialog:
    """Tests for RenameDialog."""

    def test_construction(self):
        _get_qapp()
        from vivghidra.ui_dialogs import RenameDialog
        dialog = RenameDialog(current_name="old_func_name")
        assert dialog is not None
        assert dialog.current_name == "old_func_name"

    def test_get_value_returns_new_name(self):
        _get_qapp()
        from vivghidra.ui_dialogs import RenameDialog
        dialog = RenameDialog(current_name="old_name")
        dialog.input_field.setText("new_name")
        assert dialog.get_value() == "new_name"

    def test_get_value_none_if_unchanged_empty(self):
        _get_qapp()
        from vivghidra.ui_dialogs import RenameDialog
        dialog = RenameDialog(current_name="")
        # Empty name should return None (cancel)
        dialog.input_field.setText("")
        assert dialog.get_value() is None


class TestSignatureEditDialog:
    """Tests for SignatureEditDialog."""

    def test_construction(self):
        _get_qapp()
        from vivghidra.ui_dialogs import SignatureEditDialog
        dialog = SignatureEditDialog(
            name="simple_add",
            return_type="int",
            param_types=["int", "int"],
            calling_conv="cdecl",
        )
        assert dialog is not None
        assert dialog.name_edit.text() == "simple_add"
        assert dialog.return_type_edit.text() == "int"

    def test_get_signature(self):
        _get_qapp()
        from vivghidra.ui_dialogs import SignatureEditDialog
        dialog = SignatureEditDialog(
            name="factorial",
            return_type="int",
            param_types=["int"],
            calling_conv="cdecl",
        )
        sig = dialog.get_signature()
        assert sig is not None
        assert sig["name"] == "factorial"
        assert sig["return_type"] == "int"
        assert "int" in sig["param_types"]

    def test_add_param_row(self):
        _get_qapp()
        from vivghidra.ui_dialogs import SignatureEditDialog
        dialog = SignatureEditDialog(
            name="func",
            return_type="int",
            param_types=["int"],
            calling_conv="cdecl",
        )
        dialog.add_param_row("char *", "buf")
        sig = dialog.get_signature()
        assert "char *" in sig["param_types"]

    def test_void_no_params(self):
        _get_qapp()
        from vivghidra.ui_dialogs import SignatureEditDialog
        dialog = SignatureEditDialog(
            name="nop",
            return_type="void",
            param_types=[],
            calling_conv="cdecl",
        )
        sig = dialog.get_signature()
        assert sig["return_type"] == "void"
        assert sig["param_types"] == []


class TestCSyntaxHighlighter:
    """Tests for CSyntaxHighlighter."""

    def test_construction(self):
        _get_qapp()
        from vivghidra.syntax_highlighter import CSyntaxHighlighter
        doc = QtGui.QTextDocument()
        highlighter = CSyntaxHighlighter(doc)
        assert highlighter is not None

    def test_keyword_patterns_exist(self):
        from vivghidra.syntax_highlighter import CSyntaxHighlighter
        assert hasattr(CSyntaxHighlighter, 'C_KEYWORDS')
        assert 'return' in CSyntaxHighlighter.C_KEYWORDS
        assert 'if' in CSyntaxHighlighter.C_KEYWORDS
        assert 'while' in CSyntaxHighlighter.C_KEYWORDS
        assert 'for' in CSyntaxHighlighter.C_KEYWORDS
        assert 'struct' in CSyntaxHighlighter.C_KEYWORDS

    def test_type_patterns_exist(self):
        from vivghidra.syntax_highlighter import CSyntaxHighlighter
        assert hasattr(CSyntaxHighlighter, 'C_TYPES')
        assert 'char' in CSyntaxHighlighter.C_TYPES
        assert 'long' in CSyntaxHighlighter.C_TYPES
        assert 'short' in CSyntaxHighlighter.C_TYPES

    def test_highlighting_does_not_crash(self):
        """Set text on a document with the highlighter — should not raise."""
        _get_qapp()
        from vivghidra.syntax_highlighter import CSyntaxHighlighter
        doc = QtGui.QTextDocument()
        highlighter = CSyntaxHighlighter(doc)
        # Set some C code — the highlighter should process it without error
        doc.setPlainText("int main(int argc, char **argv) {\n  return 0;\n}\n")
        # No exception means pass
        assert doc.toPlainText() is not None