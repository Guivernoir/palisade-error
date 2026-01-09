# Comprehensive test runner for palisade_errors

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     PALISADE ERRORS - COMPREHENSIVE TEST SUITE        ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Track results
FAILED=0

run_test() {
    echo -e "${YELLOW}▶${NC} $1"
    if eval "$2"; then
        echo -e "${GREEN}✓${NC} $1 passed"
        echo ""
    else
        echo -e "${RED}✗${NC} $1 failed"
        echo ""
        FAILED=1
    fi
}

# ============================================================================
# STANDARD TESTS
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  STANDARD UNIT TESTS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "All features" "cargo test --all-features --verbose"
run_test "No default features" "cargo test --no-default-features --verbose"
run_test "Tokio feature only" "cargo test --features tokio --verbose"
run_test "Async-std feature only" "cargo test --features async-std --verbose"
run_test "Obfuscate-codes feature" "cargo test --features obfuscate-codes --verbose"

# ============================================================================
# PROPERTY-BASED TESTS
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PROPERTY-BASED TESTS (PROPTEST)"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Proptest suite" "cargo test --test proptest_suite --verbose -- --test-threads=1"

# ============================================================================
# EXAMPLES
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  EXAMPLES COMPILATION AND EXECUTION"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Basic usage example" "cargo run --example basic_usage"
run_test "Sensitive context example" "cargo run --example sensitive_context"
run_test "Honeypot pipeline example" "cargo run --example honeypot_pipeline"
run_test "Production logging example" "cargo run --example logging"
run_test "Ring buffer demo" "cargo run --example ring_buffer_demo"
run_test "Async timing example" "cargo run --example async_timing --features tokio"
run_test "Obfuscation demo" "cargo run --example obfuscation_demo --features obfuscate-codes"

# ============================================================================
# CLIPPY AND FORMATTING
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  CODE QUALITY CHECKS"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Clippy (all features)" "cargo clippy --all-features --all-targets -- -D warnings"
run_test "Format check" "cargo fmt --all -- --check"

# ============================================================================
# DOCUMENTATION
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  DOCUMENTATION BUILD"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

run_test "Documentation build" "cargo doc --all-features --no-deps --verbose"

# ============================================================================
# SUMMARY
# ============================================================================

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  TEST SUMMARY"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}✓ ALL TESTS PASSED${NC}"
    echo ""
    exit 0
else
    echo -e "${RED}✗ SOME TESTS FAILED${NC}"
    echo ""
    exit 1
fi