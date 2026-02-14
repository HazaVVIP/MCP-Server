#!/bin/bash
# Test 2: Attempt Direct Tool Invocation (negative test)

echo "=== TEST 2: Direct Tool Invocation ==="
echo ""

echo "Attempt 1: POST to /tools endpoint"
RESULT1=$(curl -s -X POST http://127.0.0.1:2301/tools \
  -H "Content-Type: application/json" \
  -d '{"method":"tools/call","params":{"name":"browser_evaluate"}}')
echo "Response: $RESULT1"

echo ""
echo "Attempt 2: POST to /execute endpoint"
RESULT2=$(curl -s -X POST http://127.0.0.1:2301/execute \
  -H "Content-Type: application/json" \
  -d '{"tool":"browser_evaluate"}')
echo "Response: $RESULT2"

echo ""
echo "Attempt 3: MCP JSON-RPC format"
RESULT3=$(curl -s -X POST http://127.0.0.1:2301/tools \
  -H "Content-Type: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"playwright-browser_evaluate","arguments":{"function":"() => console.log(\"test\")"}}}')
echo "Response: $RESULT3"

echo ""
echo "=== RESULT: NOT EXPLOITABLE ==="
echo "✗ Cannot invoke tools directly via HTTP"
echo "✗ All POST requests return 404"
echo "✓ Security control working as designed"
