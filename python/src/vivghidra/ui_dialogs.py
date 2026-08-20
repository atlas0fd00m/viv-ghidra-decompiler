"""
Qt dialogs for UI interactions: rename, signature editing, comment input.

These dialogs allow the user to interact with the decompiled code:
- RenameDialog: rename a function or data symbol
- SignatureEditDialog: edit a function's return type, parameters, calling convention
- CommentDialog: input a comment for an address

All dialogs are designed to work within Vivisect's Qt-based GUI.
"""

from __future__ import annotations

import logging
from typing import Optional

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

    class RenameDialog(QtWidgets.QDialog):
        """
        Dialog for renaming a symbol (function or data).

        Usage:
            dialog = RenameDialog(current_name="old_func")
            if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                new_name = dialog.get_value()
                if new_name:
                    # apply rename...
        """

        def __init__(self, current_name: str = "", parent=None):
            super().__init__(parent)
            self.current_name = current_name
            self.setWindowTitle("Rename Symbol")
            self._build_ui()

        def _build_ui(self):
            layout = QtWidgets.QVBoxLayout(self)

            # Current name label
            current_label = QtWidgets.QLabel(f"Current name: {self.current_name}")
            current_label.setStyleSheet("color: gray; font-style: italic;")
            layout.addWidget(current_label)

            # New name input
            layout.addWidget(QtWidgets.QLabel("New name:"))
            self.input_field = QtWidgets.QLineEdit(self.current_name)
            self.input_field.selectAll()
            layout.addWidget(self.input_field)

            # Buttons
            btn_layout = QtWidgets.QHBoxLayout()
            self.ok_btn = QtWidgets.QPushButton("OK")
            self.ok_btn.clicked.connect(self._on_ok)
            self.cancel_btn = QtWidgets.QPushButton("Cancel")
            self.cancel_btn.clicked.connect(self.reject)
            btn_layout.addWidget(self.ok_btn)
            btn_layout.addWidget(self.cancel_btn)
            layout.addLayout(btn_layout)

        def _on_ok(self):
            if self.input_field.text().strip():
                self.accept()
            else:
                # Empty name — reject (treat as cancel)
                self.reject()

        def get_value(self) -> Optional[str]:
            """
            Get the new name from the dialog.
            Returns None if the name is empty (treated as cancelled).
            """
            text = self.input_field.text().strip()
            return text if text else None


    class CommentDialog(QtWidgets.QDialog):
        """
        Dialog for entering a comment at an address.

        Usage:
            dialog = CommentDialog(address="0x401156", existing_comment="")
            if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                comment = dialog.get_comment()
        """

        def __init__(self, address: str = "", existing_comment: str = "", parent=None):
            super().__init__(parent)
            self.address = address
            self.setWindowTitle("Add Comment")
            self._build_ui(existing_comment)

        def _build_ui(self, existing_comment: str):
            layout = QtWidgets.QVBoxLayout(self)

            # Address label
            addr_label = QtWidgets.QLabel(f"Address: {self.address}")
            addr_label.setStyleSheet("font-weight: bold;")
            layout.addWidget(addr_label)

            # Comment text area
            layout.addWidget(QtWidgets.QLabel("Comment:"))
            self.text_edit = QtWidgets.QPlainTextEdit(existing_comment)
            self.text_edit.setPlaceholderText("Enter comment...")
            layout.addWidget(self.text_edit)

            # Buttons
            btn_layout = QtWidgets.QHBoxLayout()
            self.ok_btn = QtWidgets.QPushButton("OK")
            self.ok_btn.clicked.connect(self.accept)
            self.cancel_btn = QtWidgets.QPushButton("Cancel")
            self.cancel_btn.clicked.connect(self.reject)
            btn_layout.addWidget(self.ok_btn)
            btn_layout.addWidget(self.cancel_btn)
            layout.addLayout(btn_layout)

        def get_comment(self) -> str:
            """Get the comment text from the dialog."""
            return self.text_edit.toPlainText().strip()


    class SignatureEditDialog(QtWidgets.QDialog):
        """
        Dialog for editing a function signature.

        Allows editing:
        - Function name
        - Return type
        - Calling convention
        - Parameters (type + name pairs, add/remove rows)

        Usage:
            dialog = SignatureEditDialog(
                name="simple_add",
                return_type="int",
                param_types=["int", "int"],
                calling_conv="cdecl",
            )
            if dialog.exec() == QtWidgets.QDialog.DialogCode.Accepted:
                sig = dialog.get_signature()
                # sig = {name, return_type, param_types, calling_conv}
        """

        def __init__(self, name: str = "", return_type: str = "void",
                     param_types: list[str] = None, calling_conv: str = "cdecl",
                     parent=None):
            super().__init__(parent)
            self.setWindowTitle("Edit Function Signature")
            self._param_rows: list[tuple[QtWidgets.QLineEdit, QtWidgets.QLineEdit]] = []
            self._build_ui(name, return_type, param_types or [], calling_conv)

        def _build_ui(self, name: str, return_type: str,
                      param_types: list[str], calling_conv: str):
            layout = QtWidgets.QVBoxLayout(self)

            # Function name
            name_layout = QtWidgets.QHBoxLayout()
            name_layout.addWidget(QtWidgets.QLabel("Name:"))
            self.name_edit = QtWidgets.QLineEdit(name)
            name_layout.addWidget(self.name_edit)
            layout.addLayout(name_layout)

            # Return type
            ret_layout = QtWidgets.QHBoxLayout()
            ret_layout.addWidget(QtWidgets.QLabel("Return type:"))
            self.return_type_edit = QtWidgets.QLineEdit(return_type)
            ret_layout.addWidget(self.return_type_edit)
            layout.addLayout(ret_layout)

            # Calling convention
            conv_layout = QtWidgets.QHBoxLayout()
            conv_layout.addWidget(QtWidgets.QLabel("Calling convention:"))
            self.calling_conv_edit = QtWidgets.QLineEdit(calling_conv)
            conv_layout.addWidget(self.calling_conv_edit)
            layout.addLayout(conv_layout)

            # Parameters section
            layout.addWidget(QtWidgets.QLabel("Parameters:"))
            self.params_container = QtWidgets.QVBoxLayout()
            layout.addLayout(self.params_container)

            # Add existing params
            for pt in param_types:
                self.add_param_row(pt, f"param{len(self._param_rows)}")

            # Add/Remove param buttons
            param_btn_layout = QtWidgets.QHBoxLayout()
            self.add_param_btn = QtWidgets.QPushButton("+ Add Parameter")
            self.add_param_btn.clicked.connect(lambda: self.add_param_row("", ""))
            self.remove_param_btn = QtWidgets.QPushButton("- Remove Last")
            self.remove_param_btn.clicked.connect(self.remove_last_param_row)
            param_btn_layout.addWidget(self.add_param_btn)
            param_btn_layout.addWidget(self.remove_param_btn)
            layout.addLayout(param_btn_layout)

            # OK/Cancel
            btn_layout = QtWidgets.QHBoxLayout()
            self.ok_btn = QtWidgets.QPushButton("OK")
            self.ok_btn.clicked.connect(self.accept)
            self.cancel_btn = QtWidgets.QPushButton("Cancel")
            self.cancel_btn.clicked.connect(self.reject)
            btn_layout.addWidget(self.ok_btn)
            btn_layout.addWidget(self.cancel_btn)
            layout.addLayout(btn_layout)

        def add_param_row(self, type_str: str = "", name_str: str = "") -> None:
            """Add a parameter row (type + name inputs)."""
            row_layout = QtWidgets.QHBoxLayout()

            type_edit = QtWidgets.QLineEdit(type_str)
            type_edit.setPlaceholderText("type (e.g., int, char*)")
            type_edit.setStyleSheet("max-width: 150px;")

            name_edit = QtWidgets.QLineEdit(name_str)
            name_edit.setPlaceholderText("name")
            name_edit.setStyleSheet("max-width: 100px;")

            row_layout.addWidget(type_edit)
            row_layout.addWidget(name_edit)

            # Insert before the add/remove buttons
            self.params_container.addLayout(row_layout)
            self._param_rows.append((type_edit, name_edit))

        def remove_last_param_row(self) -> None:
            """Remove the last parameter row."""
            if not self._param_rows:
                return
            type_edit, name_edit = self._param_rows.pop()
            # Remove the widgets
            type_edit.setParent(None)
            name_edit.setParent(None)
            type_edit.deleteLater()
            name_edit.deleteLater()

        def get_signature(self) -> dict:
            """
            Get the signature from the dialog.

            Returns:
                {name, return_type, param_types, calling_conv}
            """
            param_types = []
            for type_edit, name_edit in self._param_rows:
                t = type_edit.text().strip()
                if t:
                    param_types.append(t)

            return {
                "name": self.name_edit.text().strip(),
                "return_type": self.return_type_edit.text().strip() or "void",
                "param_types": param_types,
                "calling_conv": self.calling_conv_edit.text().strip() or "cdecl",
            }


else:
    # Stubs for headless environments
    class RenameDialog:
        def __init__(self, *args, **kwargs):
            raise ImportError("Qt required for RenameDialog")

    class CommentDialog:
        def __init__(self, *args, **kwargs):
            raise ImportError("Qt required for CommentDialog")

    class SignatureEditDialog:
        def __init__(self, *args, **kwargs):
            raise ImportError("Qt required for SignatureEditDialog")