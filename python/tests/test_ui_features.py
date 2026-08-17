"""
Unit tests for UI feature models: CommentRequest, RenameRequest, SignatureRequest.

Tests serialization, address formatting, and round-trip conversions.
"""

import pytest
from vivghidra.models import (
    CommentRequest, RenameRequest, SignatureRequest,
    SymbolInfo, DecompileRequest,
)


class TestCommentRequest:
    """Tests for CommentRequest model."""

    def test_basic_construction(self):
        req = CommentRequest(address=0x401156, comment="This is a comment")
        assert req.address == 0x401156
        assert req.comment == "This is a comment"

    def test_to_dict_address_is_hex_string(self):
        req = CommentRequest(address=0x401156, comment="test")
        d = req.to_dict()
        assert d["address"] == "0x401156"
        assert d["comment"] == "test"

    def test_to_dict_round_trip(self):
        req = CommentRequest(address=0x401156, comment="round trip")
        d = req.to_dict()
        req2 = CommentRequest.from_dict(d)
        assert req2.address == 0x401156
        assert req2.comment == "round trip"

    def test_empty_comment(self):
        req = CommentRequest(address=0x401000, comment="")
        d = req.to_dict()
        assert d["comment"] == ""

    def test_multiline_comment(self):
        comment = "Line 1\nLine 2\nLine 3"
        req = CommentRequest(address=0x401000, comment=comment)
        d = req.to_dict()
        assert d["comment"] == comment
        req2 = CommentRequest.from_dict(d)
        assert req2.comment == comment


class TestRenameRequest:
    """Tests for RenameRequest model."""

    def test_function_rename(self):
        req = RenameRequest(address=0x401156, name="my_function", is_function=True)
        d = req.to_dict()
        assert d["address"] == "0x401156"
        assert d["name"] == "my_function"
        assert d["is_function"] is True

    def test_data_rename(self):
        req = RenameRequest(address=0x404000, name="global_var", is_function=False)
        d = req.to_dict()
        assert d["is_function"] is False

    def test_round_trip(self):
        req = RenameRequest(address=0x401156, name="renamed_func", is_function=True)
        req2 = RenameRequest.from_dict(req.to_dict())
        assert req2.name == "renamed_func"
        assert req2.is_function is True

    def test_empty_name(self):
        req = RenameRequest(address=0x401000, name="", is_function=True)
        d = req.to_dict()
        assert d["name"] == ""


class TestSignatureRequest:
    """Tests for SignatureRequest model."""

    def test_basic_signature(self):
        req = SignatureRequest(
            address=0x401156,
            name="simple_add",
            return_type="int",
            param_types=["int", "int"],
            calling_conv="cdecl",
        )
        d = req.to_dict()
        assert d["address"] == "0x401156"
        assert d["name"] == "simple_add"
        assert d["return_type"] == "int"
        assert d["param_types"] == ["int", "int"]
        assert d["calling_conv"] == "cdecl"

    def test_void_return_no_params(self):
        req = SignatureRequest(
            address=0x401000,
            name="nop_func",
            return_type="void",
            param_types=[],
            calling_conv="cdecl",
        )
        d = req.to_dict()
        assert d["return_type"] == "void"
        assert d["param_types"] == []

    def test_round_trip(self):
        req = SignatureRequest(
            address=0x401156,
            name="factorial",
            return_type="int",
            param_types=["int"],
            calling_conv="cdecl",
        )
        req2 = SignatureRequest.from_dict(req.to_dict())
        assert req2.name == "factorial"
        assert req2.return_type == "int"
        assert req2.param_types == ["int"]

    def test_pointer_param_types(self):
        req = SignatureRequest(
            address=0x401200,
            name="strcpy",
            return_type="char *",
            param_types=["char *", "const char *"],
            calling_conv="cdecl",
        )
        d = req.to_dict()
        assert "char *" in d["param_types"]
        assert "const char *" in d["param_types"]

    def test_default_calling_conv(self):
        req = SignatureRequest(
            address=0x401000,
            name="func",
            return_type="int",
            param_types=["int"],
        )
        assert req.calling_conv == "cdecl"