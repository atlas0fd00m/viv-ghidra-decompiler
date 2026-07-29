#!/usr/bin/env bash
# Run all tests for the Vivisect-Ghidra bridge:
#   1. Python unit tests (pytest, 84 tests)
#   2. Java unit tests (JUnit 5, 27 tests — JsonUtil + JsonRpcServer)
#   3. Integration tests (Python, 6 tests — p-code translation + client-server)
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
FAIL=0

echo "═══════════════════════════════════════════════════════════════"
echo "  Vivisect-Ghidra Bridge — Full Test Suite"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── 1. Python unit tests ───
echo "─── Phase 1-3: Python Unit Tests ───"
cd "$SCRIPT_DIR/python"
python3 -m pytest tests/ -v --tb=short || FAIL=1
echo ""

# ─── 2. Java unit tests ───
echo "─── Phase 2: Java Unit Tests ───"
cd "$SCRIPT_DIR/java"

JUNIT_JARS="/tmp/junit/*"
JUNIT_CP="/tmp/junit/junit-jupiter-api.jar:/tmp/junit/junit-jupiter-params.jar:/tmp/junit/opentest4j.jar:/tmp/junit/apiguardian.jar"

# Check if JUnit jars exist
if [ ! -f /tmp/junit/junit-platform-console.jar ]; then
    echo "JUnit jars not found. Downloading..."
    mkdir -p /tmp/junit && cd /tmp/junit
    curl -sL -o junit-platform-console.jar https://repo1.maven.org/maven2/org/junit/platform/junit-platform-console-standalone/1.10.2/junit-platform-console-standalone-1.10.2.jar
    curl -sL -o junit-jupiter-api.jar https://repo1.maven.org/maven2/org/junit/jupiter/junit-jupiter-api/5.10.2/junit-jupiter-api-5.10.2.jar
    curl -sL -o junit-jupiter-engine.jar https://repo1.maven.org/maven2/org/junit/jupiter/junit-jupiter-engine/5.10.2/junit-jupiter-engine-5.10.2.jar
    curl -sL -o junit-jupiter-params.jar https://repo1.maven.org/maven2/org/junit/jupiter/junit-jupiter-params/5.10.2/junit-jupiter-params-5.10.2.jar
    curl -sL -o opentest4j.jar https://repo1.maven.org/maven2/org/opentest4j/opentest4j/1.3.0/opentest4j-1.3.0.jar
    curl -sL -o apiguardian.jar https://repo1.maven.org/maven2/org/apiguardian/apiguardian-api/1.1.2/apiguardian-api-1.1.2.jar
    cd "$SCRIPT_DIR/java"
fi

# Compile main source (JsonUtil, Protocol, JsonRpcServer — no Ghidra deps)
mkdir -p build/classes build/test-classes
javac -classpath "$JUNIT_CP" -d build/classes -proc:none \
    src/main/java/vivghidra/JsonUtil.java \
    src/main/java/vivghidra/Protocol.java \
    src/main/java/vivghidra/JsonRpcServer.java 2>&1

# Compile test source
javac -classpath "$JUNIT_CP:build/classes" -d build/test-classes -proc:none \
    src/test/java/vivghidra/JsonUtilTest.java \
    src/test/java/vivghidra/JsonRpcServerTest.java 2>&1

# Run tests
java -classpath "$JUNIT_JARS:build/classes:build/test-classes" \
    org.junit.platform.console.ConsoleLauncher \
    --select-package vivghidra \
    --details summary 2>&1 || FAIL=1
echo ""

# ─── 3. Integration tests ───
echo "─── Phase 4: Integration Tests ───"
cd "$SCRIPT_DIR"
python3 tests/integration_test.py || FAIL=1
echo ""

# ─── Summary ───
echo "═══════════════════════════════════════════════════════════════"
if [ $FAIL -eq 0 ]; then
    echo "  ALL TESTS PASSED"
else
    echo "  SOME TESTS FAILED"
fi
echo "═══════════════════════════════════════════════════════════════"

exit $FAIL