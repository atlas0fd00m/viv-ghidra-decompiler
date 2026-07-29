"""
JSON-RPC TCP client for communicating with the Ghidra background process.

Protocol: newline-delimited JSON over TCP.
Each request is a single-line JSON object: {"method": "...", "params": {...}}
Each response is a single-line JSON object: {"result": ...} or {"error": ...}

This mirrors the pattern documented in the Ghidra plugin development skill.
"""

from __future__ import annotations

import json
import socket
import logging
from typing import Any, Optional

from .models import DecompileRequest, DecompileResult, PcodeOp
from .config import Config

logger = logging.getLogger(__name__)


class GhidraConnectionError(Exception):
    """Raised when the connection to Ghidra fails."""
    pass


class GhidraClient:
    """
    TCP client for the Ghidra background process.

    Usage:
        client = GhidraClient(config)
        client.connect()
        status = client.ping()
        result = client.decompile_function(0x401000)
        client.close()

    The client is NOT thread-safe. Use one client per thread.
    """

    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
        self._sock: Optional[socket.socket] = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        """Establish TCP connection to the Ghidra server."""
        if self._connected:
            return
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.config.timeout)
            self._sock.connect((self.config.host, self.config.port))
            self._connected = True
            logger.info(f"Connected to Ghidra at {self.config.host}:{self.config.port}")
        except (socket.error, ConnectionRefusedError) as e:
            raise GhidraConnectionError(
                f"Cannot connect to Ghidra at {self.config.host}:{self.config.port}: {e}"
            ) from e

    def close(self) -> None:
        """Close the TCP connection."""
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None
            self._connected = False

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def _send_request(self, method: str, params: dict | None = None) -> dict:
        """
        Send a JSON-RPC request and receive the response.

        Raises GhidraConnectionError if not connected or on socket errors.
        """
        if not self._connected or self._sock is None:
            raise GhidraConnectionError("Not connected to Ghidra server")

        request = {"method": method}
        if params:
            request["params"] = params

        try:
            data = (json.dumps(request) + "\n").encode("utf-8")
            self._sock.sendall(data)

            # Read response until newline
            buf = b""
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    raise GhidraConnectionError("Connection closed by Ghidra server")
                buf += chunk
                if b"\n" in buf:
                    line, buf = buf.split(b"\n", 1)
                    break

            response = json.loads(line.decode("utf-8"))
            if "error" in response:
                raise GhidraConnectionError(f"Ghidra error: {response['error']}")
            return response.get("result", {})

        except socket.timeout as e:
            raise GhidraConnectionError(f"Timeout communicating with Ghidra: {e}") from e
        except socket.error as e:
            self._connected = False
            raise GhidraConnectionError(f"Socket error: {e}") from e
        except json.JSONDecodeError as e:
            raise GhidraConnectionError(f"Invalid JSON from Ghidra: {e}") from e

    # ─── Protocol methods ───

    def ping(self) -> dict:
        """Ping the Ghidra server — returns {pong: true, version: str}."""
        return self._send_request("ping")

    def get_status(self) -> dict:
        """Get server status — returns {program_loaded: bool, program_name: str}."""
        return self._send_request("get_status")

    def decompile_function(self, request: DecompileRequest) -> DecompileResult:
        """
        Request decompilation of a function.

        Args:
            request: DecompileRequest with address, mode, symbols, and/or pcode

        Returns:
            DecompileResult with C pseudocode and/or high p-code
        """
        result = self._send_request("decompile_function", request.to_dict())
        return DecompileResult.from_dict(result)

    def get_pcode(self, address: int) -> dict:
        """Get raw p-code for a function at the given address."""
        return self._send_request("get_pcode", {"address": address})

    def apply_symbols(self, symbols: list[dict]) -> dict:
        """Apply symbol information to the Ghidra program."""
        return self._send_request("apply_symbols", {"symbols": symbols})

    def get_function_list(self) -> dict:
        """Get list of all functions in the Ghidra program."""
        return self._send_request("get_function_list")

    def set_decompiler_options(self, options: dict) -> dict:
        """Set decompiler options."""
        return self._send_request("set_decompiler_options", {"options": options})