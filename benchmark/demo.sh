#!/bin/bash

# Kyber Benchmark Demo Script
# This script demonstrates the benchmarking tool with various configurations

set -e

echo "=================================="
echo "Kyber Benchmark Demonstration"
echo "=================================="

# Build the project
echo "Building the project..."
make build

# Function to run a test and capture the result
run_test() {
    local test_name="$1"
    local server_args="$2"
    local client_args="$3"
    
    echo ""
    echo "Running: $test_name"
    echo "----------------------------------------"
    
    # Start server in background
    ./bin/server $server_args &
    SERVER_PID=$!
    
    # Wait for server to start
    sleep 2
    
    # Run client
    ./bin/client $client_args
    
    # Stop server
    kill $SERVER_PID 2>/dev/null || true
    wait $SERVER_PID 2>/dev/null || true
    
    echo "Test completed: $test_name"
    sleep 1
}

# Test 1: Basic encrypted benchmark
run_test "Basic Encrypted Test" \
    "-port 8080" \
    "-server localhost:8080 -size 1024 -count 1000"

# Test 2: Unencrypted baseline
run_test "Unencrypted Baseline" \
    "-port 8081 -crypto=false" \
    "-server localhost:8081 -crypto=false -size 1024 -count 1000"

# Test 3: Large packet test
run_test "Large Packet Test" \
    "-port 8082" \
    "-server localhost:8082 -size 32768 -count 500"

# Test 4: Multi-worker test
run_test "Multi-Worker Test" \
    "-port 8083" \
    "-server localhost:8083 -size 4096 -count 2000 -workers 4"

# Test 5: High-throughput test
run_test "High-Throughput Test" \
    "-port 8084" \
    "-server localhost:8084 -size 65536 -count 1000 -workers 2"

echo ""
echo "=================================="
echo "All tests completed successfully!"
echo "=================================="
echo ""
echo "To run individual tests:"
echo "  ./bin/server [options] &"
echo "  ./bin/client [options]"
echo ""
echo "For more options:"
echo "  ./bin/server -help"
echo "  ./bin/client -help"
echo ""
echo "Check README.md for detailed usage instructions."
