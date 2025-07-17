#!/bin/bash

# Comprehensive build validation script for ghostnet
# This script ensures all components build correctly before shipping

set -e  # Exit on any error

echo "🔍 Starting comprehensive build validation..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

success_count=0
total_tests=0

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    ((total_tests++))
    echo -e "${YELLOW}Running: $test_name${NC}"
    
    if eval "$test_cmd"; then
        echo -e "${GREEN}✅ $test_name PASSED${NC}"
        ((success_count++))
    else
        echo -e "${RED}❌ $test_name FAILED${NC}"
        return 1
    fi
}

# Clean previous builds
echo "🧹 Cleaning previous builds..."
rm -rf zig-cache zig-out

# Build validation tests
run_test "Debug build" "zig build"
run_test "Release build" "zig build -Doptimize=ReleaseSafe"
run_test "Release fast build" "zig build -Doptimize=ReleaseFast"
run_test "Release small build" "zig build -Doptimize=ReleaseSmall"

# Run all tests
run_test "Module tests" "zig build test"

# Build examples to ensure they compile
echo "🔧 Building examples..."
for example in examples/*.zig; do
    if [[ -f "$example" ]]; then
        example_name=$(basename "$example" .zig)
        run_test "Example: $example_name" "zig build-exe '$example' --name '$example_name' --dep ghostnet --mod ghostnet:src/root.zig -freference-trace"
    fi
done

# Check for common issues
echo "🔍 Checking for common issues..."
run_test "No TODO markers in main code" "! grep -r 'TODO\\|FIXME\\|XXX' src/ || true"
run_test "No debug prints in release code" "! grep -r 'std.debug.print' src/ || true"
run_test "All source files have proper headers" "find src/ -name '*.zig' -exec grep -l '//' {} \\; | wc -l"

# Final report
echo ""
echo "📊 Build validation complete!"
echo -e "Tests passed: ${GREEN}$success_count${NC}/$total_tests"

if [ $success_count -eq $total_tests ]; then
    echo -e "${GREEN}🎉 All validation tests passed! Ready to ship.${NC}"
    exit 0
else
    echo -e "${RED}❌ Some tests failed. Please fix issues before shipping.${NC}"
    exit 1
fi