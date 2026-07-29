#!/usr/bin/env bash
# Start Ghidra headless with the Vivisect-Ghidra bridge plugin
# Usage: ./start_ghidra_headless.sh /path/to/binary [--extra-args]
set -e

BINARY="${1:?Usage: $0 /path/to/binary}"
shift || true

GHIDRA_HOME="${GHIDRA_INSTALL_DIR:-/opt/ghidra}"
PROJECT_DIR="/tmp/vivghidra-ghidra-project"
PROJECT_NAME="vivghidra"
PLUGIN_DIR="$(cd "$(dirname "$0")/.." && pwd)/java/build/libs"

mkdir -p "$PROJECT_DIR"

echo "Starting Ghidra headless with bridge plugin..."
echo "  Binary:      $BINARY"
echo "  Ghidra:      $GHIDRA_HOME"
echo "  Project:     $PROJECT_DIR/$PROJECT_NAME"
echo "  Plugin:      $PLUGIN_DIR"

"$GHIDRA_HOME/support/analyzeHeadless" \
    "$PROJECT_DIR" "$PROJECT_NAME" \
    -import "$BINARY" \
    -overwrite \
    -postScript "$GHIDRA_HOME/Ghidra/Features/Decompile/ghidra_scripts/StartBridgeServer.java" \
    -pluginPath "$PLUGIN_DIR" \
    "$@"