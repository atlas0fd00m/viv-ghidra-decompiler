"""
Configuration for the Vivisect–Ghidra bridge.

Connection settings are read from environment variables with sensible defaults.
"""

import os

# Default connection settings
DEFAULT_HOST = "localhost"
DEFAULT_PORT = 13100
DEFAULT_TIMEOUT = 30          # seconds for decompile requests
DEFAULT_DECOMPILE_TIMEOUT = 60  # seconds for Ghidra decompiler itself

# Environment variable names
ENV_HOST = "VIVGHIDRA_HOST"
ENV_PORT = "VIVGHIDRA_PORT"
ENV_TIMEOUT = "VIVGHIDRA_TIMEOUT"
ENV_GHIDRA_HOME = "GHIDRA_INSTALL_DIR"
ENV_VIV_EXT_PATH = "VIV_EXT_PATH"


class Config:
    """Configuration object — read once at extension load time."""

    def __init__(self):
        self.host = os.environ.get(ENV_HOST, DEFAULT_HOST)
        self.port = int(os.environ.get(ENV_PORT, DEFAULT_PORT))
        self.timeout = int(os.environ.get(ENV_TIMEOUT, DEFAULT_TIMEOUT))
        self.decompile_timeout = DEFAULT_DECOMPILE_TIMEOUT
        self.ghidra_home = os.environ.get(ENV_GHIDRA_HOME, "")
        self.arch = "amd64"  # will be set from workspace at runtime

    def __repr__(self) -> str:
        return f"Config(host={self.host!r}, port={self.port}, timeout={self.timeout})"

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "timeout": self.timeout,
            "decompile_timeout": self.decompile_timeout,
            "ghidra_home": self.ghidra_home,
            "arch": self.arch,
        }