#!/bin/bash
set -e

# Integration tests for Parachute
# Usage: ./run_tests.sh

PARACHUTE_URL="http://localhost:18080"
PROXY_URL="http://localhost:18888"
AUTH_HEADER="Authorization: Basic $(echo -n 'admin:testpass123' | base64)"

echo "=== Parachute Integration Tests ==="
echo ""

# Wait for services to be ready
echo "Waiting for Parachute to be ready..."
for i in {1..30}; do
    if curl -s "$PARACHUTE_URL/health" > /dev/null 2>&1; then
        echo "Parachute is ready!"
        break
    fi
    sleep 1
done

PASSED=0
FAILED=0

test_case() {
    local name="$1"
    local expected="$2"
    local actual="$3"

    if echo "$actual" | grep -q "$expected"; then
        echo "✓ $name"
        PASSED=$((PASSED + 1))
    else
        echo "✗ $name (expected: $expected)"
        echo "  Actual: $actual"
        FAILED=$((FAILED + 1))
    fi
}

# Test 1: Health endpoint (no auth required)
echo ""
echo "--- Health Check Tests ---"
RESULT=$(curl -s "$PARACHUTE_URL/health")
test_case "Health endpoint returns ok" '"status":"ok"' "$RESULT"

RESULT=$(curl -s "$PARACHUTE_URL/healthz")
test_case "Healthz endpoint returns ok" '"status":"ok"' "$RESULT"

# Test 2: Auth required for protected endpoints
echo ""
echo "--- Authentication Tests ---"
RESULT=$(curl -s "$PARACHUTE_URL/api/pending")
test_case "API requires auth" '"error"' "$RESULT"

RESULT=$(curl -s -H "$AUTH_HEADER" "$PARACHUTE_URL/api/pending")
test_case "API works with valid auth" '\[' "$RESULT"

# Test 3: Command blocking
echo ""
echo "--- Command Interception Tests ---"

# Safe command - should be allowed
RESULT=$(curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": "ls -la"}}')
test_case "Safe command allowed" "received" "$RESULT"

# Blocked command - should be blocked
RESULT=$(curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": "rm -rf /"}}')
test_case "Destructive command blocked" '"error"' "$RESULT"

# Shell wrapper with blocked command - should be blocked
RESULT=$(curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": "bash -c \"rm -rf /\""}}')
test_case "Shell-wrapped destructive command blocked" '"error"' "$RESULT"

# Fork bomb - should be blocked
RESULT=$(curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": ":(){ :|:& };:"}}')
test_case "Fork bomb blocked" '"error"' "$RESULT"

# Test 4: Approval-required commands
echo ""
echo "--- Approval Queue Tests ---"

# Get pending count before
BEFORE=$(curl -s -H "$AUTH_HEADER" "$PARACHUTE_URL/api/pending" | grep -o '\[' | wc -l)

# Command requiring approval (run in background since it blocks)
curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": "sudo apt update"}}' \
    --max-time 2 > /dev/null 2>&1 &
PENDING_PID=$!

sleep 1

# Check pending queue
RESULT=$(curl -s -H "$AUTH_HEADER" "$PARACHUTE_URL/api/pending")
test_case "Command added to pending queue" 'sudo' "$RESULT"

# Get pending command ID
PENDING_ID=$(echo "$RESULT" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)

if [ -n "$PENDING_ID" ]; then
    # Approve the command
    RESULT=$(curl -s -X POST "$PARACHUTE_URL/api/approve/$PENDING_ID" -H "$AUTH_HEADER")
    test_case "Command can be approved" 'success' "$RESULT"
fi

# Kill the waiting request
kill $PENDING_PID 2>/dev/null || true

# Test 5: PII detection
echo ""
echo "--- PII Detection Tests ---"

# Request with credit card number
RESULT=$(curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": "echo 4111111111111111"}}')
test_case "Credit card PII blocked" '"error"' "$RESULT"

# Request with AWS key
RESULT=$(curl -s -X POST "$PARACHUTE_URL/proxy/execute" \
    -H "$AUTH_HEADER" \
    -H "Content-Type: application/json" \
    -d '{"name": "bash", "args": {"command": "export AWS_KEY=AKIAIOSFODNN7EXAMPLE"}}')
test_case "AWS key PII blocked" '"error"' "$RESULT"

# Test 6: Rate limiting
echo ""
echo "--- Rate Limiting Tests ---"
# Make many requests quickly
for i in {1..65}; do
    curl -s -H "$AUTH_HEADER" "$PARACHUTE_URL/api/pending" > /dev/null
done
RESULT=$(curl -s -H "$AUTH_HEADER" "$PARACHUTE_URL/api/pending")
# Note: This may or may not trigger rate limit depending on timing
echo "Rate limit test: completed 65 requests"

# Summary
echo ""
echo "=== Test Summary ==="
echo "Passed: $PASSED"
echo "Failed: $FAILED"
echo ""

if [ $FAILED -gt 0 ]; then
    echo "Some tests failed!"
    exit 1
else
    echo "All tests passed!"
    exit 0
fi
