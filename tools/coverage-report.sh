#!/bin/bash
#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# Generate code coverage report using gcov/lcov
#
# Usage: ./tools/coverage-report.sh [--html] [--threshold N]
#
# Options:
#   --html        Generate HTML report (requires genhtml)
#   --threshold N Fail if coverage is below N% (default: 0, disabled)
#   --clean       Clean build directory before building
#   --help        Show this help message
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${PROJECT_ROOT}/build-coverage"
COVERAGE_DIR="${PROJECT_ROOT}/coverage-report"

GENERATE_HTML=0
THRESHOLD=0
CLEAN=0

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --html)
            GENERATE_HTML=1
            shift
            ;;
        --threshold)
            THRESHOLD="$2"
            shift 2
            ;;
        --clean)
            CLEAN=1
            shift
            ;;
        --help)
            echo "Usage: $0 [--html] [--threshold N] [--clean]"
            echo ""
            echo "Options:"
            echo "  --html        Generate HTML report (requires genhtml)"
            echo "  --threshold N Fail if coverage is below N% (default: 0, disabled)"
            echo "  --clean       Clean build directory before building"
            echo "  --help        Show this help message"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check for required tools
check_tool() {
    if ! command -v "$1" &> /dev/null; then
        echo "Error: $1 is required but not installed."
        echo "Install with: $2"
        exit 1
    fi
}

check_tool lcov "brew install lcov (macOS) or apt install lcov (Linux)"
if [[ $GENERATE_HTML -eq 1 ]]; then
    check_tool genhtml "brew install lcov (macOS) or apt install lcov (Linux)"
fi

cd "${PROJECT_ROOT}"

# Clean if requested
if [[ $CLEAN -eq 1 ]] && [[ -d "${BUILD_DIR}" ]]; then
    echo "==> Cleaning build directory..."
    rm -rf "${BUILD_DIR}"
fi

# Configure
echo "==> Configuring with coverage preset..."
cmake --preset dev-coverage

# Build
echo "==> Building..."
cmake --build "${BUILD_DIR}" -j "$(nproc 2>/dev/null || sysctl -n hw.ncpu)"

# Run tests
echo "==> Running tests..."
ctest --test-dir "${BUILD_DIR}" --output-on-failure || true

# Capture coverage data
echo "==> Capturing coverage data..."
lcov --capture \
    --directory "${BUILD_DIR}" \
    --output-file "${BUILD_DIR}/coverage.info" \
    --ignore-errors mismatch

# Remove system headers and test files from coverage
echo "==> Filtering coverage data..."
lcov --remove "${BUILD_DIR}/coverage.info" \
    '/usr/*' \
    '/opt/*' \
    '*/unit_tests/*' \
    '*/test_*' \
    '*/lib/Catch2/*' \
    '*/lib/yamlcpp/*' \
    '*/lib/swoc/*' \
    --output-file "${BUILD_DIR}/coverage-filtered.info" \
    --ignore-errors unused

# Generate summary
echo ""
echo "==> Coverage Summary:"
lcov --summary "${BUILD_DIR}/coverage-filtered.info" 2>&1 | tee "${BUILD_DIR}/coverage-summary.txt"

# Extract coverage percentage
COVERAGE=$(lcov --summary "${BUILD_DIR}/coverage-filtered.info" 2>&1 | grep "lines" | grep -oP '\d+\.\d+%' | head -1 | tr -d '%')

if [[ -z "$COVERAGE" ]]; then
    # Try alternative parsing for different lcov versions
    COVERAGE=$(lcov --summary "${BUILD_DIR}/coverage-filtered.info" 2>&1 | grep -oE '[0-9]+\.[0-9]+%' | head -1 | tr -d '%')
fi

echo ""
echo "Line coverage: ${COVERAGE:-unknown}%"

# Generate HTML report if requested
if [[ $GENERATE_HTML -eq 1 ]]; then
    echo "==> Generating HTML report..."
    rm -rf "${COVERAGE_DIR}"
    genhtml "${BUILD_DIR}/coverage-filtered.info" \
        --output-directory "${COVERAGE_DIR}" \
        --title "ATS Code Coverage" \
        --legend \
        --show-details
    echo ""
    echo "HTML report generated at: ${COVERAGE_DIR}/index.html"
fi

# Check threshold
if [[ $THRESHOLD -gt 0 ]] && [[ -n "$COVERAGE" ]]; then
    COVERAGE_INT=${COVERAGE%.*}
    if [[ $COVERAGE_INT -lt $THRESHOLD ]]; then
        echo ""
        echo "ERROR: Coverage ${COVERAGE}% is below threshold ${THRESHOLD}%"
        exit 1
    fi
    echo "Coverage ${COVERAGE}% meets threshold ${THRESHOLD}%"
fi

echo ""
echo "==> Coverage report complete!"
echo "Raw coverage data: ${BUILD_DIR}/coverage.info"
echo "Filtered coverage: ${BUILD_DIR}/coverage-filtered.info"
echo "Summary: ${BUILD_DIR}/coverage-summary.txt"
