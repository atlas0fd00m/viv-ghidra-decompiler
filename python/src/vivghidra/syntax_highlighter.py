"""
C syntax highlighter for the decompiler widget.

Uses QSyntaxHighlighter to apply color formatting to C pseudocode
returned by Ghidra's decompiler.

Color scheme:
- Keywords (int, void, if, return, etc.): blue, bold
- Types (char, long, short, etc.): purple
- Strings ("...", '...'): green
- Comments (// ... and /* ... */): gray, italic
- Numbers (0x401156, 42, etc.): orange
- Function names (word followed by '('): dark blue, bold
- Preprocessor (#include, #define): gray
"""

from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

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

    class CSyntaxHighlighter(QtGui.QSyntaxHighlighter):
        """
        Syntax highlighter for C pseudocode.

        Usage:
            doc = text_edit.document()
            highlighter = CSyntaxHighlighter(doc)
            # Now any text set on the text edit will be highlighted
        """

        # C keywords (control flow + common language keywords)
        C_KEYWORDS = [
            'auto', 'break', 'case', 'const', 'continue', 'default', 'do',
            'else', 'enum', 'extern', 'for', 'goto', 'if', 'inline',
            'register', 'restrict', 'return', 'sizeof', 'static', 'struct',
            'switch', 'typedef', 'union', 'volatile', 'while',
            'undefined', 'ushort', 'uchar', 'uint', 'ulong',
        ]

        # C types (and common Ghidra decompiler types)
        C_TYPES = [
            'int', 'void', 'char', 'long', 'short', 'float', 'double',
            'signed', 'unsigned', 'bool', 'size_t', 'ssize_t',
            'ptrdiff_t', 'wchar_t', 'int8_t', 'int16_t', 'int32_t',
            'int64_t', 'uint8_t', 'uint16_t', 'uint32_t', 'uint64_t',
            'undefined1', 'undefined2', 'undefined4', 'undefined8',
        ]

        def __init__(self, parent: QtGui.QTextDocument):
            super().__init__(parent)
            self._init_formats()

        def _init_formats(self):
            """Create text formats for each category."""
            # Keyword format — blue, bold
            self.keyword_format = QtGui.QTextCharFormat()
            self.keyword_format.setForeground(QtGui.QColor("#569CD6"))  # VS Code blue
            self.keyword_format.setFontWeight(QtGui.QFont.Weight.Bold)

            # Type format — purple/teal
            self.type_format = QtGui.QTextCharFormat()
            self.type_format.setForeground(QtGui.QColor("#4EC9B0"))  # VS Code teal
            self.type_format.setFontWeight(QtGui.QFont.Weight.Bold)

            # String format — green
            self.string_format = QtGui.QTextCharFormat()
            self.string_format.setForeground(QtGui.QColor("#CE9178"))  # VS Code rust

            # Comment format — gray, italic
            self.comment_format = QtGui.QTextCharFormat()
            self.comment_format.setForeground(QtGui.QColor("#6A9955"))  # VS Code green-gray
            self.comment_format.setFontItalic(True)

            # Number format — orange
            self.number_format = QtGui.QTextCharFormat()
            self.number_format.setForeground(QtGui.QColor("#B5CEA8"))  # VS Code light green

            # Function name format — dark blue, bold
            self.funcname_format = QtGui.QTextCharFormat()
            self.funcname_format.setForeground(QtGui.QColor("#DCDCAA"))  # VS Code yellow
            self.funcname_format.setFontWeight(QtGui.QFont.Weight.Bold)

            # Preprocessor format — gray
            self.preproc_format = QtGui.QTextCharFormat()
            self.preproc_format.setForeground(QtGui.QColor("#C586C0"))  # VS Code purple

            # Address annotation format — gray italic (for /* 0x... */ comments)
            self.address_format = QtGui.QTextCharFormat()
            self.address_format.setForeground(QtGui.QColor("#808080"))
            self.address_format.setFontItalic(True)

        def highlightBlock(self, text: str) -> None:
            """Apply syntax highlighting to a block of text."""
            # Single-line comments: // ...
            self._highlight_regex(text, r'//[^\n]*', self.comment_format)

            # Multi-line comments: /* ... */ (single line only — cross-line handled by block state)
            self._highlight_regex(text, r'/\*.*?\*/', self.comment_format)

            # Strings: "..." and '...'
            self._highlight_regex(text, r'"(?:\\.|[^"\\])*"', self.string_format)
            self._highlight_regex(text, r"'(?:\\.|[^'\\])*'", self.string_format)

            # Preprocessor: #...
            self._highlight_regex(text, r'#\w+', self.preproc_format)

            # Keywords — word boundary match
            for kw in self.C_KEYWORDS:
                self._highlight_regex(text, r'\b' + re.escape(kw) + r'\b', self.keyword_format)

            # Types — word boundary match
            for tp in self.C_TYPES:
                self._highlight_regex(text, r'\b' + re.escape(tp) + r'\b', self.type_format)

            # Numbers: hex, decimal, octal
            self._highlight_regex(text, r'\b0x[0-9a-fA-F]+\b', self.number_format)
            self._highlight_regex(text, r'\b[0-9]+\b', self.number_format)

            # Function names: identifier followed by '('
            self._highlight_regex(text, r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*\(', self.funcname_format)

        def _highlight_regex(self, text: str, pattern: str, fmt: QtGui.QTextCharFormat) -> None:
            """Apply a format to all matches of a regex in the current block."""
            for match in re.finditer(pattern, text):
                start = match.start()
                end = match.end()
                # For function name regex, don't include the '('
                if pattern.endswith(r'\('):
                    end -= 1
                self.setFormat(start, end - start, fmt)

else:
    # Stub for headless environments
    class CSyntaxHighlighter:
        """Stub — Qt not available."""
        C_KEYWORDS = []
        C_TYPES = []

        def __init__(self, *args, **kwargs):
            raise ImportError("PySide6 or PyQt5 is required for CSyntaxHighlighter")