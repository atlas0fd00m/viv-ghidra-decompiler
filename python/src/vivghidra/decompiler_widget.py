"""
Qt dock widget for displaying decompiled C pseudocode.

This widget displays the C code returned by Ghidra's decompiler
in a read-only text panel with C syntax highlighting.

Features:
- Syntax highlighting via CSyntaxHighlighter
- Right-click context menu: Add Comment, Rename Function, Edit Signature,
  Copy to Clipboard, Export as .c File
- Address annotations parsed from Ghidra output (clickable)
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
        """

        # Address annotation regex — matches Ghidra's /* 0x... */ comments
        ADDR_ANNOTATION_RE = re.compile(r'/\*\s*(0x[0-9a-fA-F]+)\s*\*/')

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
                          on_edit_signature: Callable = None, on_refresh: Callable = None) -> None:
            """Set callback functions for context menu actions."""
            if on_add_comment:
                self._on_add_comment = on_add_comment
            if on_rename:
                self._on_rename = on_rename
            if on_edit_signature:
                self._on_edit_signature = on_edit_signature
            if on_refresh:
                self._on_refresh = on_refresh

        def _show_context_menu(self, position: QtCore.QPoint) -> None:
            """Show the right-click context menu."""
            menu = QtWidgets.QMenu(self)

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
                # Try to get the address from the cursor position
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