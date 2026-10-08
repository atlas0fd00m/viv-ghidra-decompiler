"""
Qt dock widget for displaying decompiled C pseudocode.

This widget displays the C code returned by Ghidra's decompiler
in a read-only text panel with C syntax highlighting.

Features:
- Syntax highlighting via CSyntaxHighlighter
- Right-click context menu: Add Comment, Rename Function, Edit Signature,
  Copy to Clipboard, Export as .c File
- Cross-referencing: click a function name → navigate to that function in Vivisect
- Clickable address annotations: /* 0x... */ → navigate to address in Vivisect
- Search/filter bar for finding text in decompiled output
- Connection status and decompilation timing
"""

from __future__ import annotations

import logging
import re
import time
from typing import Optional, Callable, Any

logger = logging.getLogger(__name__)

# Qt imports — wrapped in try/except so the module can be imported
# without PySide6/PyQt5 installed (for headless testing)
try:
    from PySide6 import QtCore, QtGui, QtWidgets
    QT_AVAILABLE = True
except ImportError:
    try:
        from PyQt5 import QtCore, QtGui, QtWidgets
        QT_AVAILABLE = True
    except ImportError:
        QT_AVAILABLE = False


if QT_AVAILABLE:

    class DecompilerWidget(QtWidgets.QWidget):
        """
        Dock widget displaying decompiled C pseudocode.

        Layout:
        ┌─────────────────────────────────┐
        │ [function name]    [status]     │  ← header bar
        ├─────────────────────────────────┤
        │ [Search: _______________] [×]   │  ← search bar
        ├─────────────────────────────────┤
        │                                 │
        │  int main(int argc, char **argv)│
        │  {                               │
        │      return 0;                   │
        │  }                               │
        │                                 │
        ├─────────────────────────────────┤
        │ Ready | 0.42s | localhost:13100 │  ← status bar
        └─────────────────────────────────┘

        Right-click context menu:
        - Add Comment
        - Rename Function
        - Edit Signature
        - Copy to Clipboard
        - Export as .c File

        Click behavior:
        - Click a function name → navigate to that function in Vivisect
        - Click a /* 0x... */ address → navigate to that address
        """

        # Address annotation regex — matches Ghidra's /* 0x... */ comments
        ADDR_ANNOTATION_RE = re.compile(r'/\*\s*(0x[0-9a-fA-F]+)\s*\*/')

        # Function call/definition regex — identifier followed by (
        FUNC_NAME_RE = re.compile(r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(')

        # C keywords/types to exclude from function name extraction
        _C_KEYWORDS_AND_TYPES = {
            'int', 'void', 'char', 'long', 'short', 'float', 'double',
            'unsigned', 'signed', 'if', 'else', 'for', 'while', 'return',
            'switch', 'case', 'break', 'continue', 'do', 'goto', 'sizeof',
            'struct', 'union', 'enum', 'typedef', 'const', 'static',
            'extern', 'register', 'auto', 'volatile', 'inline',
            'bool', 'size_t', 'undefined', 'undefined1', 'undefined2',
            'undefined4', 'undefined8', 'ushort', 'uchar', 'uint', 'ulong',
        }

        def __init__(self, vw, vwgui, parent=None):
            super().__init__(parent)
            self.vw = vw
            self.vwgui = vwgui
            self._decompile_time = 0.0
            self._func_name = ""
            self._func_addr: Optional[int] = None
            self._c_code = ""
            self._decompile_start = 0.0

            # Callbacks — set by extension.py
            self._on_add_comment: Optional[Callable] = None
            self._on_rename: Optional[Callable] = None
            self._on_edit_signature: Optional[Callable] = None
            self._on_refresh: Optional[Callable] = None
            self._on_navigate: Optional[Callable] = None

            # Search state
            self._search_results: list[int] = []  # positions in document
            self._search_index = 0

            self._build_ui()
            self.setWindowTitle("Ghidra Decompiler")

        def _build_ui(self):
            layout = QtWidgets.QVBoxLayout(self)

            # Header bar
            header = QtWidgets.QHBoxLayout()
            self.func_label = QtWidgets.QLabel("No function loaded")
            self.func_label.setStyleSheet("font-weight: bold; font-size: 14px; padding: 4px;")
            header.addWidget(self.func_label)
            header.addStretch()

            self.refresh_btn = QtWidgets.QPushButton("Refresh")
            self.refresh_btn.clicked.connect(self._handle_refresh)
            header.addWidget(self.refresh_btn)

            layout.addLayout(header)

            # Search bar
            search_layout = QtWidgets.QHBoxLayout()
            self.search_bar = QtWidgets.QLineEdit()
            self.search_bar.setPlaceholderText("Search in decompiled code...")
            self.search_bar.setClearButtonEnabled(True)
            self.search_bar.textChanged.connect(self._on_search_changed)
            self.search_bar.returnPressed.connect(self._on_search_next)
            search_layout.addWidget(self.search_bar)

            self.search_next_btn = QtWidgets.QPushButton("Next")
            self.search_next_btn.clicked.connect(self._on_search_next)
            search_layout.addWidget(self.search_next_btn)

            self.search_status = QtWidgets.QLabel("")
            self.search_status.setStyleSheet("color: gray; font-size: 11px;")
            search_layout.addWidget(self.search_status)

            layout.addLayout(search_layout)

            # Code display
            self.code_display = QtWidgets.QTextEdit()
            self.code_display.setReadOnly(True)
            self.code_display.setFont(QtGui.QFont("Courier", 10))
            self.code_display.setPlaceholderText(
                "Right-click a function and select 'Ghidra Decompile' to see C pseudocode here."
            )
            # Install syntax highlighter
            try:
                from .syntax_highlighter import CSyntaxHighlighter
                self._highlighter = CSyntaxHighlighter(self.code_display.document())
            except Exception as e:
                logger.debug(f"Syntax highlighter not available: {e}")
                self._highlighter = None

            # Enable right-click context menu
            self.code_display.setContextMenuPolicy(QtCore.Qt.ContextMenuPolicy.CustomContextMenu)
            self.code_display.customContextMenuRequested.connect(self._show_context_menu)

            # Enable click navigation
            self.code_display.mousePressEvent = self._on_code_click

            layout.addWidget(self.code_display)

            # Status bar
            status_bar = QtWidgets.QHBoxLayout()
            self.status_label = QtWidgets.QLabel("Ready")
            self.time_label = QtWidgets.QLabel("")
            self.conn_label = QtWidgets.QLabel("")
            status_bar.addWidget(self.status_label)
            status_bar.addStretch()
            status_bar.addWidget(self.time_label)
            status_bar.addWidget(self.conn_label)
            layout.addLayout(status_bar)

        def set_code(self, c_code: str, func_name: str = "", func_addr: int = None) -> None:
            """Display decompiled C code."""
            self._c_code = c_code
            self._func_name = func_name
            if func_addr is not None:
                self._func_addr = func_addr

            self._decompile_time = time.time() - self._decompile_start if hasattr(self, '_decompile_start') else 0.0

            self.func_label.setText(func_name or "Unknown function")
            self.code_display.setPlainText(c_code)
            self.status_label.setText("Decompiled")
            self.time_label.setText(f"{self._decompile_time:.2f}s")

            # Clear search when new code is loaded
            self.clear_search()

        def set_error(self, error_msg: str) -> None:
            """Display an error message."""
            self.status_label.setText("Error")
            self.code_display.setPlainText(f"// ERROR: {error_msg}")
            self.time_label.setText("")

        def set_connection_status(self, connected: bool, host: str = "", port: int = 0) -> None:
            """Update the connection status indicator."""
            if connected:
                self.conn_label.setText(f"● {host}:{port}")
                self.conn_label.setStyleSheet("color: green;")
            else:
                self.conn_label.setText("● Disconnected")
                self.conn_label.setStyleSheet("color: red;")

        def set_callbacks(self, on_add_comment: Callable = None, on_rename: Callable = None,
                          on_edit_signature: Callable = None, on_refresh: Callable = None,
                          on_navigate: Callable = None) -> None:
            """Set callback functions for context menu actions and navigation."""
            if on_add_comment:
                self._on_add_comment = on_add_comment
            if on_rename:
                self._on_rename = on_rename
            if on_edit_signature:
                self._on_edit_signature = on_edit_signature
            if on_refresh:
                self._on_refresh = on_refresh
            if on_navigate:
                self._on_navigate = on_navigate

        def set_navigation_callback(self, callback: Callable) -> None:
            """Set the navigation callback — called when user clicks an address or function name."""
            self._on_navigate = callback

        # ─── Cross-referencing & navigation ───

        def _on_code_click(self, event) -> None:
            """
            Handle mouse clicks on the code display.

            Ctrl+click (or just click) on:
            - A /* 0x... */ address → navigate to that address in Vivisect
            - A function name → navigate to that function in Vivisect
            """
            # First, let the QTextEdit handle its normal selection/cursor behavior
            super(QTextEdit, self.code_display).mousePressEvent(event)

            # Check if we have a navigation callback
            if not self._on_navigate:
                return

            cursor = self.code_display.cursorForPosition(event.pos())
            line_text = cursor.block().text()

            # Check if click is on an address annotation
            addr = self._get_address_at_position(cursor)
            if addr is not None:
                self._navigate_to_address(addr)
                return

            # Check if click is on a function name
            func_name = self._get_function_name_at_position(cursor)
            if func_name is not None:
                # Look up the function address in Vivisect
                func_addr = self._lookup_function_address(func_name)
                if func_addr is not None:
                    self._navigate_to_address(func_addr)

        def _get_address_at_position(self, cursor) -> Optional[int]:
            """
            Check if the cursor is on or near a /* 0x... */ address annotation.
            Returns the address as int, or None.
            """
            line_text = cursor.block().text()
            cursor_pos = cursor.positionInBlock()

            # Find all address annotations on this line
            for match in self.ADDR_ANNOTATION_RE.finditer(line_text):
                start = match.start()
                end = match.end()
                if start <= cursor_pos <= end:
                    return int(match.group(1), 16)

            return None

        def _get_function_name_at_position(self, cursor) -> Optional[str]:
            """
            Check if the cursor is on a function name (identifier followed by '(').
            Returns the function name, or None.
            """
            line_text = cursor.block().text()
            cursor_pos = cursor.positionInBlock()

            for match in self.FUNC_NAME_RE.finditer(line_text):
                name = match.group(1)
                if name in self._C_KEYWORDS_AND_TYPES:
                    continue
                start = match.start(1)
                end = match.end(1)
                if start <= cursor_pos <= end:
                    return name

            return None

        def _lookup_function_address(self, name: str) -> Optional[int]:
            """
            Look up a function's address by name in the Vivisect workspace.
            Returns the address, or None if not found.
            """
            if self.vw is None:
                return None
            try:
                # Vivisect's getName returns the VA for a given name
                # or we can search through functions
                for fva in self.vw.getFunctions():
                    func_name = self.vw.getName(fva) or ""
                    if func_name == name:
                        return fva
            except Exception:
                pass
            return None

        def _navigate_to_address(self, addr: int) -> None:
            """Navigate to an address in Vivisect's disassembly view."""
            if self._on_navigate:
                logger.debug(f"Navigating to 0x{addr:x}")
                self._on_navigate(addr)
            else:
                logger.debug("No navigation callback set")

        def get_function_names(self) -> list[str]:
            """
            Extract all function names from the current C code.

            Returns a list of unique function names (excluding C keywords/types).
            """
            names = []
            seen = set()
            for match in self.FUNC_NAME_RE.finditer(self._c_code):
                name = match.group(1)
                if name not in self._C_KEYWORDS_AND_TYPES and name not in seen:
                    names.append(name)
                    seen.add(name)
            return names

        # ─── Search ───

        def search_text(self, query: str) -> list[int]:
            """
            Search for text in the decompiled code.

            Args:
                query: text to search for

            Returns:
                List of character positions where the text was found
            """
            if not query:
                self.clear_search()
                return []

            results = []
            text = self._c_code
            start = 0
            while True:
                pos = text.find(query, start)
                if pos == -1:
                    break
                results.append(pos)
                start = pos + len(query)

            self._search_results = results
            self._search_index = 0

            # Update status
            if results:
                self.search_status.setText(f"{len(results)} found")
                self._highlight_search_result(0)
            else:
                self.search_status.setText("No results")

            return results

        def _highlight_search_result(self, index: int) -> None:
            """Highlight the search result at the given index."""
            if not self._search_results:
                return

            pos = self._search_results[index]
            query_len = len(self.search_bar.text())

            cursor = self.code_display.textCursor()
            cursor.setPosition(pos)
            cursor.setPosition(pos + query_len, QtGui.QTextCursor.MoveMode.KeepAnchor)
            self.code_display.setTextCursor(cursor)

            # Scroll to the result
            self.code_display.ensureCursorVisible()

        def _on_search_changed(self, text: str) -> None:
            """Handle search bar text changes — live search."""
            if not text:
                self.clear_search()
            else:
                self.search_text(text)

        def _on_search_next(self) -> None:
            """Cycle to the next search result."""
            if not self._search_results:
                # Try searching with current text
                text = self.search_bar.text()
                if text:
                    self.search_text(text)
                return

            self._search_index = (self._search_index + 1) % len(self._search_results)
            self._highlight_search_result(self._search_index)
            self.search_status.setText(f"{self._search_index + 1}/{len(self._search_results)}")

        def clear_search(self) -> None:
            """Clear the search and reset highlighting."""
            self.search_bar.clear()
            self._search_results = []
            self._search_index = 0
            self.search_status.setText("")

        # ─── Context menu ───

        def _show_context_menu(self, position: QtCore.QPoint) -> None:
            """Show the right-click context menu."""
            menu = QtWidgets.QMenu(self)

            # Navigate to address under cursor
            addr = self._get_address_at_cursor()
            if addr is not None:
                nav_action = menu.addAction(f"Navigate to 0x{addr:x}")
                nav_action.triggered.connect(lambda: self._navigate_to_address(addr))
                menu.addSeparator()

            # Add Comment
            add_comment_action = menu.addAction("Add Comment")
            add_comment_action.triggered.connect(self._handle_add_comment)

            # Rename Function
            rename_action = menu.addAction("Rename Function")
            rename_action.triggered.connect(self._handle_rename)

            # Edit Signature
            sig_action = menu.addAction("Edit Signature")
            sig_action.triggered.connect(self._handle_edit_signature)

            menu.addSeparator()

            # Copy to Clipboard
            copy_action = menu.addAction("Copy to Clipboard")
            copy_action.triggered.connect(self._handle_copy)

            # Export as .c File
            export_action = menu.addAction("Export as .c File")
            export_action.triggered.connect(self._handle_export)

            menu.exec(self.code_display.mapToGlobal(position))

        def _handle_add_comment(self) -> None:
            """Handle 'Add Comment' context menu action."""
            if self._on_add_comment:
                addr = self._get_address_at_cursor()
                self._on_add_comment(addr or self._func_addr, self._func_name)
            else:
                logger.debug("No add_comment callback set")

        def _handle_rename(self) -> None:
            """Handle 'Rename Function' context menu action."""
            if self._on_rename:
                self._on_rename(self._func_addr, self._func_name)
            else:
                logger.debug("No rename callback set")

        def _handle_edit_signature(self) -> None:
            """Handle 'Edit Signature' context menu action."""
            if self._on_edit_signature:
                self._on_edit_signature(self._func_addr, self._func_name)
            else:
                logger.debug("No edit_signature callback set")

        def _handle_copy(self) -> None:
            """Copy the C code to the clipboard."""
            clipboard = QtWidgets.QApplication.clipboard()
            clipboard.setText(self._c_code)

        def _handle_export(self) -> None:
            """Export the C code to a .c file."""
            filename, _ = QtWidgets.QFileDialog.getSaveFileName(
                self, "Export C Code", "", "C Files (*.c)"
            )
            if filename:
                try:
                    with open(filename, 'w') as f:
                        f.write(self._c_code)
                except Exception as e:
                    logger.error(f"Export failed: {e}")

        def _handle_refresh(self) -> None:
            """Re-decompile the current function."""
            if self._on_refresh:
                self._decompile_start = time.time()
                self._on_refresh(self._func_addr)
            else:
                logger.debug("No refresh callback set")

        def _get_address_at_cursor(self) -> Optional[int]:
            """
            Try to extract an address from the C code at the cursor position.
            Looks for /* 0x... */ address annotations on the current line.
            """
            cursor = self.code_display.textCursor()
            line = cursor.block().text()
            match = self.ADDR_ANNOTATION_RE.search(line)
            if match:
                return int(match.group(1), 16)
            return None

        def get_address_annotations(self) -> list[int]:
            """
            Extract all address annotations from the current C code.
            Returns a list of addresses found in /* 0x... */ comments.
            """
            addresses = []
            for match in self.ADDR_ANNOTATION_RE.finditer(self._c_code):
                addr = int(match.group(1), 16)
                if addr not in addresses:
                    addresses.append(addr)
            return addresses


else:
    # Stub class for headless environments without Qt
    class DecompilerWidget:
        """Stub — Qt not available."""
        def __init__(self, *args, **kwargs):
            raise ImportError("PySide6 or PyQt5 is required for DecompilerWidget")