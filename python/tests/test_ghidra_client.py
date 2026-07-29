"""
Unit tests for the GhidraClient JSON-RPC TCP client.

Uses a mock TCP server to test request/response handling
without requiring a real Ghidra instance.
"""

import json
import pytest
import socket

from vivghidra.config import Config
from vivghidra.ghidra_client import GhidraClient, GhidraConnectionError
from vivghidra.models import DecompileRequest, DecompileResult


class TestGhidraClientConnection:
    """Tests for connection management."""

    def test_connect_and_close(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        client = GhidraClient(cfg)
        assert not client.connected
        client.connect()
        assert client.connected
        client.close()
        assert not client.connected

    def test_context_manager(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            assert client.connected
        assert not client.connected

    def test_connection_refused(self):
        cfg = Config()
        cfg.host = "127.0.0.1"
        cfg.port = 1  # nobody listening on port 1
        cfg.timeout = 2

        client = GhidraClient(cfg)
        with pytest.raises(GhidraConnectionError):
            client.connect()

    def test_request_when_not_connected(self):
        client = GhidraClient()
        with pytest.raises(GhidraConnectionError, match="Not connected"):
            client.ping()


class TestGhidraClientProtocol:
    """Tests for JSON-RPC protocol methods."""

    def test_ping(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.ping()
            assert result["pong"] is True
            assert "version" in result

    def test_get_status(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.get_status()
            assert result["program_loaded"] is True
            assert "program_name" in result

    def test_decompile_function(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            req = DecompileRequest(address=0x401000, mode="standard")
            result = client.decompile_function(req)
            assert isinstance(result, DecompileResult)
            assert result.success is True
            assert "main" in result.c_code
            assert result.function_name == "main"

    def test_get_function_list(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.get_function_list()
            assert "functions" in result
            assert len(result["functions"]) > 0

    def test_apply_symbols(self, mock_server):
        cfg = Config()
        cfg.host = mock_server.host
        cfg.port = mock_server.port
        cfg.timeout = 5

        with GhidraClient(cfg) as client:
            result = client.apply_symbols([{"name": "foo", "address": "0x401000"}])
            assert "ok" in result


class TestGhidraClientConfig:
    """Tests for Config integration."""

    def test_default_config(self):
        cfg = Config()
        assert cfg.host == "localhost"
        assert cfg.port == 13100

    def test_config_from_env(self, monkeypatch):
        monkeypatch.setenv("VIVGHIDRA_HOST", "remote.host")
        monkeypatch.setenv("VIVGHIDRA_PORT", "9999")
        monkeypatch.setenv("VIVGHIDRA_TIMEOUT", "45")
        cfg = Config()
        assert cfg.host == "remote.host"
        assert cfg.port == 9999
        assert cfg.timeout == 45

    def test_config_to_dict(self):
        cfg = Config()
        d = cfg.to_dict()
        assert "host" in d
        assert "port" in d
        assert "timeout" in d