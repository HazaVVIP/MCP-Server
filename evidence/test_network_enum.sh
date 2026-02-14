#!/bin/bash
# Test 5: Network enumeration from this environment

echo "=== TEST 5: Network Enumeration ==="
echo ""

echo "Step 1: Check current network"
ip addr show | grep -E "inet |UP"

echo ""
echo "Step 2: Check routing"
ip route

echo ""
echo "Step 3: Test internet connectivity"
echo -n "Google DNS (8.8.8.8): "
ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 && echo "✓ Reachable" || echo "✗ Not reachable"

echo -n "Cloudflare DNS (1.1.1.1): "
ping -c 1 -W 2 1.1.1.1 >/dev/null 2>&1 && echo "✓ Reachable" || echo "✗ Not reachable"

echo ""
echo "Step 4: Test HTTP connectivity"
echo -n "http://example.com: "
curl -s -m 3 http://example.com >/dev/null 2>&1 && echo "✓ Reachable" || echo "✗ Blocked"

echo -n "https://github.com: "
curl -s -m 3 https://github.com >/dev/null 2>&1 && echo "✓ Reachable" || echo "✗ Blocked"

echo ""
echo "Step 5: Test internal network access"
echo "Scanning localhost ports..."
for port in 80 443 3000 5000 8080 8081 9000; do
  echo -n "  Port $port: "
  timeout 1 bash -c "echo >/dev/tcp/127.0.0.1/$port" 2>/dev/null && echo "✓ Open" || echo "✗ Closed"
done

echo ""
echo "Step 6: Test cloud metadata endpoint"
echo -n "AWS metadata (169.254.169.254): "
curl -s -m 2 http://169.254.169.254/latest/meta-data/ 2>&1 | head -1
echo -n "Azure metadata (169.254.169.254): "
curl -s -m 2 -H "Metadata: true" http://169.254.169.254/metadata/instance?api-version=2021-02-01 2>&1 | head -1

echo ""
echo "=== RESULT ==="
echo "Testing complete - see results above"
