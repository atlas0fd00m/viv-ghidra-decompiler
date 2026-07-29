#!/usr/bin/env bash
# Build the Vivisect-Ghidra bridge plugin without Gradle.
# Usage: ./build.sh /path/to/ghidra
set -e

GHIDRA_DIR="${1:-${GHIDRA_INSTALL_DIR:-/opt/ghidra}}"
VERSION="0.1.0"

if [ ! -d "$GHIDRA_DIR" ]; then
    echo "Error: Ghidra installation not found at: $GHIDRA_DIR"
    echo "Set GHIDRA_INSTALL_DIR or pass the path as an argument:"
    echo "  $0 /path/to/ghidra"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BUILD_DIR="$SCRIPT_DIR/build/classes"
DIST_DIR="$SCRIPT_DIR/build/dist"

echo "Building Vivisect-Ghidra bridge plugin..."
echo "  Ghidra:  $GHIDRA_DIR"
echo "  Version: $VERSION"

# Build classpath from all Ghidra jars
CLASSPATH=$(find "$GHIDRA_DIR" -name "*.jar" -type f -printf "%p:")

# Compile main source (src/main only — NOT src/test which needs JUnit)
mkdir -p "$BUILD_DIR"
find "$SCRIPT_DIR/src/main" -name "*.java" -print0 | \
    xargs -0 javac -classpath "$CLASSPATH" -d "$BUILD_DIR" -proc:none

# Package as extension zip
mkdir -p "$DIST_DIR"
cd "$BUILD_DIR"
zip -r "$DIST_DIR/vivghidra-$VERSION.zip" .
cd "$SCRIPT_DIR"
# Add extension metadata
cp extension.properties "$DIST_DIR/"
sed -i "s/@extversion@/$VERSION/g" "$DIST_DIR/extension.properties"
cp Module.manifest "$DIST_DIR/"

echo ""
echo "Build complete: $DIST_DIR/vivghidra-$VERSION.zip"
echo "Install in Ghidra: File → Install Extensions → Add ZIP"