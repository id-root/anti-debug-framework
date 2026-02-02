#!/bin/bash
# ============================================================================
# Anti-Debug Environment Matrix - Phase 2
# ============================================================================
# Tests the Anti-Debug Framework under various environments.
# Extended for Phase 2 elite detection capabilities.

set -e

BINARY="./target/debug/anti_debug_framework"
RESULTS_DIR="./experiments"

mkdir -p "$RESULTS_DIR"

if [ ! -f "$BINARY" ]; then
    echo "Binary not found. Building..."
    cargo build
    if [ ! -f "$BINARY" ]; then
        echo "Build failed."
        exit 1
    fi
fi

echo "========================================"
echo "  Anti-Debug Environment Matrix v2.0   "
echo "  Phase 2: Research-Grade Testing      "
echo "========================================"
echo ""
echo "Date: $(date -Iseconds)"
echo "Kernel: $(uname -r)"
echo "CPU: $(grep -m1 'model name' /proc/cpuinfo | cut -d':' -f2 | xargs)"
echo ""

# Function to run a test and capture output
run_test() {
    local NAME="$1"
    local CMD="$2"
    local EXPECTED="$3"
    local OUTPUT_FILE="$RESULTS_DIR/$(echo "$NAME" | tr ' ' '_' | tr '[:upper:]' '[:lower:]').json"
    
    echo "----------------------------------------"
    echo "Test: $NAME"
    echo "Command: $CMD"
    
    # Run command with timeout
    if command -v timeout >/dev/null; then
        CMD_PREFIX="timeout 30s"
    else
        CMD_PREFIX=""
    fi
    
    START_TIME=$(date +%s%N)
    OUTPUT=$(eval "$CMD_PREFIX $CMD" 2>&1) || true
    END_TIME=$(date +%s%N)
    DURATION_MS=$(( (END_TIME - START_TIME) / 1000000 ))
    EXIT_CODE=$?
    
    # Extract verdict and score
    VERDICT=$(echo "$OUTPUT" | grep -E "Final Verdict:" | head -1 || echo "N/A")
    SCORE=$(echo "$OUTPUT" | grep -E "Cumulative Score:" | head -1 || echo "N/A")
    
    echo "Duration: ${DURATION_MS}ms"
    echo "Exit Code: $EXIT_CODE"
    echo "$VERDICT"
    echo "$SCORE"
    
    # Check if expected outcome was met
    if echo "$OUTPUT" | grep -q "$EXPECTED"; then
        echo "STATUS: PASS (Expected pattern found)"
        STATUS="PASS"
    else
        echo "STATUS: CHECK (Pattern '$EXPECTED' not found)"
        STATUS="CHECK"
    fi
    
    # Save raw output to JSON
    cat > "$OUTPUT_FILE" <<EOF
{
  "test_name": "$NAME",
  "command": "$CMD",
  "timestamp": "$(date -Iseconds)",
  "duration_ms": $DURATION_MS,
  "exit_code": $EXIT_CODE,
  "status": "$STATUS",
  "expected": "$EXPECTED",
  "verdict": "$(echo "$VERDICT" | tr -d '\n')",
  "score": "$(echo "$SCORE" | tr -d '\n')",
  "raw_output_length": ${#OUTPUT}
}
EOF
    
    echo ""
}

# ============================================================================
# Phase 1 Tests (Original)
# ============================================================================

# 1. Native Execution (Baseline)
run_test "Native Execution" "$BINARY" "Clean"

# 2. Strace (Ptrace Detection)
if command -v strace >/dev/null; then
    run_test "Strace Tracing" "strace -f $BINARY 2>/dev/null" "Instrumented"
else
    echo "Skipping Strace (not installed)"
fi

# 3. GDB with Signal Pass (Trap Flag)
if command -v gdb >/dev/null; then
    run_test "GDB Signal Pass" "gdb -batch -ex 'handle SIGTRAP nostop pass' -ex 'run' -ex 'quit' $BINARY 2>/dev/null" "Instrumented"
else
    echo "Skipping GDB (not installed)"
fi

# ============================================================================
# Phase 2 Tests (Elite Extensions)
# ============================================================================

# 4. GDB with Hardware Breakpoint
if command -v gdb >/dev/null; then
    run_test "GDB Hardware BP" "gdb -batch -ex 'handle SIGTRAP nostop pass' -ex 'hbreak main' -ex 'run' -ex 'quit' $BINARY 2>/dev/null" "Instrumented"
fi

# 5. GDB with Software Breakpoint
if command -v gdb >/dev/null; then
    run_test "GDB Software BP" "gdb -batch -ex 'handle SIGTRAP nostop pass' -ex 'break main' -ex 'run' -ex 'quit' $BINARY 2>/dev/null" "Int3"
fi

# 6. QEMU User Emulation
if command -v qemu-x86_64 >/dev/null; then
    run_test "QEMU User Mode" "qemu-x86_64 $BINARY" "Instrumented"
else
    echo "Skipping QEMU (not installed)"
fi

# 7. rr Recording (if available)
if command -v rr >/dev/null; then
    run_test "rr Record" "rr record --chaos $BINARY 2>/dev/null" "RecordReplay"
else
    echo "Skipping rr (not installed)"
fi

# 8. ltrace (Library Tracing)
if command -v ltrace >/dev/null; then
    run_test "ltrace" "ltrace -e 'getpid' $BINARY 2>/dev/null" "Instrumented"
else
    echo "Skipping ltrace (not installed)"
fi

# ============================================================================
# Environment Variation Tests
# ============================================================================

# 9. Check SMT Status
echo "----------------------------------------"
echo "Environment Check: SMT Status"
SMT_STATUS=$(cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo "unknown")
echo "SMT Active: $SMT_STATUS"
echo ""

# 10. Check CPU Governor
echo "----------------------------------------"
echo "Environment Check: CPU Governor"
GOVERNOR=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo "unknown")
echo "Governor: $GOVERNOR"
echo ""

# 11. Check for Hypervisor
echo "----------------------------------------"
echo "Environment Check: Hypervisor Detection"
if grep -q "hypervisor" /proc/cpuinfo; then
    echo "Hypervisor: Present (CPUID flag set)"
    HYPERVISOR=$(dmesg 2>/dev/null | grep -i "hypervisor" | head -1 || echo "Unknown")
    echo "Details: $HYPERVISOR"
else
    echo "Hypervisor: Not detected"
fi
echo ""

# ============================================================================
# Summary
# ============================================================================

echo "========================================"
echo "Matrix Complete"
echo "========================================"
echo ""
echo "Results saved to: $RESULTS_DIR/"
ls -la "$RESULTS_DIR/"
echo ""
echo "Environment Summary:"
echo "  Kernel: $(uname -r)"
echo "  SMT: $SMT_STATUS"
echo "  Governor: $GOVERNOR"
echo "  Hypervisor: $(grep -q 'hypervisor' /proc/cpuinfo && echo 'Yes' || echo 'No')"
echo ""
echo "For detailed output, examine individual JSON files."
