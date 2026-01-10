#!/bin/bash
# Fuzzing runner for palisade_errors (without ASAN due to linker issues)
#
# Usage: ./scripts/run_fuzz.sh [target] [seconds]
#   target: error_context, truncation, metadata, ring_buffer, or "all"
#   seconds: how long to run each fuzzer (default: 60)
#
# NOTE: This version disables AddressSanitizer due to linking issues with
# some nightly toolchain versions. The fuzzing still works but won't catch
# memory safety issues. For full ASAN support, use an older nightly version.

set -e

# Colors
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

TARGET=${1:-all}
DURATION=${2:-60}

echo "╔════════════════════════════════════════════════════════╗"
echo "║     PALISADE ERRORS - FUZZING SUITE                   ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check if cargo-fuzz is installed
if ! command -v cargo-fuzz &> /dev/null; then
    echo -e "${RED}✗${NC} cargo-fuzz not found. Installing..."
    cargo +nightly install cargo-fuzz
fi

# Check if nightly toolchain is available
if ! rustup toolchain list | grep -q nightly; then
    echo -e "${YELLOW}!${NC} Nightly toolchain not found. Installing..."
    rustup install nightly
    echo ""
fi

echo -e "${BLUE}ℹ${NC} Fuzzing requires Rust nightly toolchain"
echo -e "${BLUE}ℹ${NC} Using: $(rustup +nightly --version | head -1)"
echo -e "${YELLOW}⚠${NC} Running without AddressSanitizer (linker compatibility)"
echo ""

TARGETS=("truncation" "metadata" "ring_buffer")

# Disable ASAN to avoid linker errors
export RUSTFLAGS="-Cpanic=abort"

if [ "$TARGET" = "all" ]; then
    echo "Running all fuzz targets for ${DURATION} seconds each..."
    echo ""
    
    for target in "${TARGETS[@]}"; do
        echo -e "${YELLOW}▶${NC} Fuzzing: $target"
        cargo +nightly fuzz run "$target" --sanitizer none -- -max_total_time="$DURATION" || true
        echo ""
    done
else
    echo -e "${YELLOW}▶${NC} Fuzzing: $TARGET for ${DURATION} seconds"
    cargo +nightly fuzz run "$TARGET" --sanitizer none -- -max_total_time="$DURATION"
fi

echo ""
echo -e "${GREEN}✓${NC} Fuzzing complete"
echo ""
echo "Check fuzz/artifacts/ for any crashes found"
echo ""
echo -e "${BLUE}ℹ${NC} Note: This run used --sanitizer none due to ASAN linker issues."
echo -e "${BLUE}ℹ${NC} For memory safety checking, use property-based tests:"
echo -e "${BLUE}ℹ${NC}   cargo test --test proptest_suite"
