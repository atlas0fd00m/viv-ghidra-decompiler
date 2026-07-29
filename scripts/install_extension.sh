#!/usr/bin/env bash
# Install the Vivisect-Ghidra bridge extension into Vivisect's plugin directory
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SRC_DIR="$SCRIPT_DIR/../python/src/vivghidra"

# Determine target directory
EXT_DIR="${VIV_EXT_PATH:-$HOME/.viv/plugins}"

echo "Installing vivghidra extension to: $EXT_DIR"
mkdir -p "$EXT_DIR"

# Copy the extension package
cp -r "$SRC_DIR" "$EXT_DIR/"

echo "Done. Restart Vivisect to load the extension."
echo "Set VIVGHIDRA_HOST and VIVGHIDRA_PORT to connect to the Ghidra backend."