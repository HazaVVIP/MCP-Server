#!/bin/bash
# Test 3: Process and stdio access

echo "=== TEST 3: MCP Server Process Access ==="
echo ""

echo "Step 1: Find MCP server process"
MCP_PID=$(pgrep -f "mcp/dist/index.js")
echo "✓ MCP PID: $MCP_PID"

echo ""
echo "Step 2: Check process ownership"
ps -p $MCP_PID -o user,pid,cmd
OWNER=$(ps -p $MCP_PID -o user --no-headers | tr -d ' ')
echo "Process owner: $OWNER"
CURRENT_USER=$(whoami)
echo "Current user: $CURRENT_USER"

echo ""
echo "Step 3: Check file descriptors"
if [ -d "/proc/$MCP_PID/fd" ]; then
  echo "File descriptors:"
  ls -la /proc/$MCP_PID/fd/ 2>&1 | head -10
else
  echo "✗ Cannot access /proc/$MCP_PID/fd"
fi

echo ""
echo "Step 4: Attempt to write to stdin (fd 0)"
if [ -w "/proc/$MCP_PID/fd/0" ]; then
  echo "✓ stdin is writable"
  echo "⚠️  RACE CONDITION VULNERABILITY EXISTS"
else
  echo "✗ stdin not writable (Permission denied expected)"
fi

echo ""
echo "=== RESULT ==="
if [ "$OWNER" = "$CURRENT_USER" ]; then
  echo "⚠️  Same user - may be able to access stdio"
  echo "Test outcome: Potentially exploitable in same-user context"
else
  echo "✓ Different user - cannot access stdio"
  echo "Test outcome: NOT exploitable (process isolation working)"
fi
