"""
Unit tests for new GhidraClient methods: set_comment, rename_symbol, set_signature.

Tests against the mock JSON-RPC server.
"""

import pytest
from vivghidra.config import Config
from vivghidra.ghidra_client import GhidraClient
from vivghidra.models import CommentRequest, RenameRequest, SignatureRequest


class TestGhidraClientSetComment:
    """Tests for set_comment RPC method."""

    def test_set_comment(self, mock_server_ui):
        cfg = Config()
        cfg.host = mock_server_ui.host
        cfg.port = mock_server_ui.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.set_comment("0x401156", "This is a test comment")
            assert result["success"] is True

    def test_set_comment_empty(self, mock_server_ui):
        cfg = Config()
        cfg.host = mock_server_ui.host
        cfg.port = mock_server_ui.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.set_comment("0x401000", "")
            assert result["success"] is True


class TestGhidraClientRenameSymbol:
    """Tests for rename_symbol RPC method."""

    def test_rename_function(self, mock_server_ui):
        cfg = Config()
        cfg.host = mock_server_ui.host
        cfg.port = mock_server_ui.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.rename_symbol("0x401156", "my_func", is_function=True)
            assert result["success"] is True

    def test_rename_data_symbol(self, mock_server_ui):
        cfg = Config()
        cfg.host = mock_server_ui.host
        cfg.port = mock_server_ui.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.rename_symbol("0x404000", "global_var", is_function=False)
            assert result["success"] is True


class TestGhidraClientSetSignature:
    """Tests for set_signature RPC method."""

    def test_set_signature(self, mock_server_ui):
        cfg = Config()
        cfg.host = mock_server_ui.host
        cfg.port = mock_server_ui.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.set_signature(
                "0x401156",
                name="simple_add",
                return_type="int",
                param_types=["int", "int"],
                calling_conv="cdecl",
            )
            assert result["success"] is True

    def test_set_signature_void(self, mock_server_ui):
        cfg = Config()
        cfg.host = mock_server_ui.host
        cfg.port = mock_server_ui.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.set_signature(
                "0x401000",
                name="nop",
                return_type="void",
                param_types=[],
                calling_conv="cdecl",
            )
            assert result["success"] is True