# Benchmark runner for palisade_errors

set -e

echo "╔════════════════════════════════════════════════════════╗"
echo "║     PALISADE ERRORS - BENCHMARK SUITE                 ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Colors
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m'

echo -e "${YELLOW}▶${NC} Running all benchmarks..."
echo ""

# Run benchmarks with all features
cargo bench --all-features

echo ""
echo -e "${GREEN}✓${NC} Benchmarks complete"
echo ""
echo "View detailed results at: target/criterion/report/index.html"
echo ""

# Optionally open the report in browser
if command -v xdg-open &> /dev/null; then
    echo "Opening report in browser..."
    xdg-open target/criterion/report/index.html &
elif command -v open &> /dev/null; then
    echo "Opening report in browser..."
    open target/criterion/report/index.html &
fi