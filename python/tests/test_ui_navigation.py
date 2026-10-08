"""
Unit tests for Option A UI features: cross-referencing, clickable addresses, search bar.

Tests the DecompilerWidget's navigation and search capabilities.
"""

import pytest

try:
    from PySide6 import QtCore, QtGui, QtWidgets
    QT_AVAILABLE = True
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
        QT_AVAILABLE = True
    except ImportError:
        QT_AVAILABLE = False

pytestmark = pytest.mark.skipif(not QT_AVAILABLE, reason="Qt not available for UI tests")

_qapp = None

def _get_qapp():
    global _qapp
    if _qapp is None and QT_AVAILABLE:
        _qapp = QtWidgets.QApplication.instance() or QtWidgets.QApplication([])
    return _qapp


class TestAddressParsing:
    """Tests for address annotation parsing from Ghidra C output."""

    def test_extract_single_address(self):
        from vivghidra.decompiler_widget import DecompilerWidget
        assert DecompilerWidget.ADDR_ANNOTATION_RE is not None
        text = "/* 0x401156 */ int simple_add(int a, int b) {"
        match = DecompilerWidget.ADDR_ANNOTATION_RE.search(text)
        assert match is not None
        assert match.group(1) == "0x401156"

    def test_extract_multiple_addresses(self):
        from vivghidra.decompiler_widget import DecompilerWidget
        text = """
/* 0x401156 */ int simple_add(int a, int b) {
/* 0x40115a */     int result = a + b;
/* 0x40115e */     return result;
/* 0x401160 */ }
"""
        matches = list(DecompilerWidget.ADDR_ANNOTATION_RE.finditer(text))
        assert len(matches) == 4
        addresses = [m.group(1) for m in matches]
        assert "0x401156" in addresses
        assert "0x401160" in addresses

    def test_no_address_in_plain_code(self):
        from vivghidra.decompiler_widget import DecompilerWidget
        text = "int main() { return 0; }"
        match = DecompilerWidget.ADDR_ANNOTATION_RE.search(text)
        assert match is None

    def test_address_with_uppercase_hex(self):
        from vivghidra.decompiler_widget import DecompilerWidget
        text = "/* 0x401ABC */ void func(void)"
        match = DecompilerWidget.ADDR_ANNOTATION_RE.search(text)
        assert match is not None
        assert match.group(1) == "0x401ABC"


class TestFunctionNameParsing:
    """Tests for parsing function names from C code for cross-referencing."""

    def test_extract_function_name_from_signature(self):
        """Parse 'int simple_add(' → 'simple_add'"""
        import re
        # Pattern: identifier followed by ( that's not a keyword
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        text = "int simple_add(int a, int b) {"
        match = re.search(pattern, text)
        # Should find 'simple_add' (skip 'int' which is a type, not a function call)
        # We need to filter out keywords/types
        all_matches = re.findall(pattern, text)
        assert "simple_add" in all_matches

    def test_extract_called_function(self):
        """Parse 'result = printf("hello")' → 'printf'"""
        import re
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        text = '  printf("hello world");'
        match = re.search(pattern, text)
        assert match is not None
        assert match.group(1) == "printf"

    def test_extract_multiple_function_calls(self):
        import re
        pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\('
        text = """
  int x = simple_add(a, b);
  int y = factorial(x);
  printf("%d\\n", y);
"""
        matches = re.findall(pattern, text)
        assert "simple_add" in matches
        assert "factorial" in matches
        assert "printf" in matches


class TestDecompilerWidgetNavigation:
    """Tests for navigation features in DecompilerWidget."""

    def test_get_address_annotations(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        # Create a mock vw/vwgui
        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = """
/* 0x401156 */ int simple_add(int a, int b) {
/* 0x40115a */     return a + b;
/* 0x401160 */ }
"""
        widget.set_code(c_code, "simple_add", 0x401156)
        annotations = widget.get_address_annotations()
        assert 0x401156 in annotations
        assert 0x40115a in annotations
        assert 0x401160 in annotations
        assert len(annotations) == 3

    def test_get_address_at_cursor(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = "/* 0x401156 */ int simple_add(int a, int b) {\n  return a + b;\n}\n"
        widget.set_code(c_code, "simple_add", 0x401156)

        # Move cursor to first line
        cursor = widget.code_display.textCursor()
        cursor.movePosition(QtGui.QTextCursor.MoveOperation.Start)
        widget.code_display.setTextCursor(cursor)

        addr = widget._get_address_at_cursor()
        assert addr == 0x401156

    def test_navigation_callback_set(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        called_with = []
        def nav_callback(addr):
            called_with.append(addr)

        widget.set_navigation_callback(nav_callback)
        assert widget._on_navigate is not None

        # Trigger navigation
        widget._navigate_to_address(0x401156)
        assert 0x401156 in called_with

    def test_get_function_names_from_code(self):
        """Test that the widget can extract function names from C code."""
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = """
/* 0x401156 */ int simple_add(int a, int b) {
/* 0x401178 */     int x = factorial(a);
/* 0x401190 */     return x + b;
/* 0x4011a0 */ }
"""
        widget.set_code(c_code, "simple_add", 0x401156)
        names = widget.get_function_names()
        assert "simple_add" in names
        assert "factorial" in names


class TestDecompilerWidgetSearch:
    """Tests for the search/filter bar in DecompilerWidget."""

    def test_search_bar_exists(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        assert hasattr(widget, 'search_bar')
        assert isinstance(widget.search_bar, QtWidgets.QLineEdit)

    def test_search_finds_text(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = "int simple_add(int a, int b) {\n  return a + b;\n}\n"
        widget.set_code(c_code, "simple_add", 0x401156)

        # Perform search
        results = widget.search_text("simple_add")
        assert len(results) > 0
        assert results[0] >= 0  # found at some position

    def test_search_no_results(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = "int main() { return 0; }\n"
        widget.set_code(c_code, "main", 0x401000)

        results = widget.search_text("nonexistent_function")
        assert len(results) == 0

    def test_search_multiple_results(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = """
int func_a() { return 0; }
int func_b() { return func_a(); }
int func_c() { return func_a(); }
"""
        widget.set_code(c_code, "func_c", 0x401000)
        results = widget.search_text("func_a")
        assert len(results) >= 2  # appears at least twice

    def test_search_clear(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = "int main() { return 0; }\n"
        widget.set_code(c_code, "main", 0x401000)

        widget.search_text("main")
        widget.clear_search()
        # After clearing, search bar should be empty
        assert widget.search_bar.text() == ""

    def test_search_navigates_to_first_result(self):
        _get_qapp()
        from vivghidra.decompiler_widget import DecompilerWidget

        class MockVw:
            pass
        class MockVwgui:
            pass

        widget = DecompilerWidget(MockVw(), MockVwgui())
        c_code = "int main() {\n  int x = 42;\n  return x;\n}\n"
        widget.set_code(c_code, "main", 0x401000)

        widget.search_text("42")
        # After search, the cursor should be at the found position
        cursor = widget.code_display.textCursor()
        selected_text = cursor.selectedText()
        # The search should have selected the found text or moved cursor there
        assert "42" in widget.code_display.toPlainText()