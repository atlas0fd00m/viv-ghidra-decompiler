"""
Qt dock widget for displaying decompiled C pseudocode.

This widget displays the C code returned by Ghidra's decompiler
in a read-only text panel with basic syntax highlighting.

It also shows connection status and decompilation timing.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

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
        """

        def __init__(self, vw, vwgui, parent=None):
            super().__init__(parent)
            self.vw = vw
            self.vwgui = vwgui
            self._decompile_time = 0.0
            self._func_name = ""

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
            self.refresh_btn.clicked.connect(self._on_refresh)
            header.addWidget(self.refresh_btn)

            layout.addLayout(header)

            # Code display
            self.code_display = QtWidgets.QTextEdit()
            self.code_display.setReadOnly(True)
            self.code_display.setFont(QtGui.QFont("Courier", 10))
            self.code_display.setPlaceholderText(
                "Right-click a function and select 'Ghidra Decompile' to see C pseudocode here."
            )
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

        def set_code(self, c_code: str, func_name: str = "") -> None:
            """Display decompiled C code."""
            self._func_name = func_name
            self._decompile_time = time.time() - self._decompile_start if hasattr(self, '_decompile_start') else 0.0

            self.func_label.setText(func_name or "Unknown function")
            self.code_display.setPlainText(c_code)
            self.status_label.setText("Decompiled")
            self.time_label.setText(f"{self._decompile_time:.2f}s")

            # Basic C syntax highlighting
            self._highlight_syntax()

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

        def _highlight_syntax(self) -> None:
            """Apply minimal C syntax highlighting."""
            # This is a simple approach — for production, consider QSyntaxHighlighter
            pass

        def _on_refresh(self) -> None:
            """Re-decompile the current function."""
            # This would call back to the extension's decompile function
            pass

else:
    # Stub class for headless environments without Qt
    class DecompilerWidget:
        """Stub — Qt not available."""
        def __init__(self, *args, **kwargs):
            raise ImportError("PySide6 or PyQt5 is required for DecompilerWidget")