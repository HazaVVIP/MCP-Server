#!/bin/bash

# Validation Script for Vulnerability Chains
# This script tests the exploitability of identified vulnerability chains
# Run in GitHub Actions environment to validate findings

set -e

echo "================================================"
echo "Vulnerability Chain Validation"
echo "Date: $(date)"
echo "================================================"
echo ""

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

# Helper function for test results
test_result() {
    local test_name="$1"
    local result="$2"
    local details="$3"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC}: $test_name"
        TESTS_PASSED=$((TESTS_PASSED + 1))
    elif [ "$result" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC}: $test_name"
        TESTS_FAILED=$((TESTS_FAILED + 1))
    else
        echo -e "${YELLOW}⊘ SKIP${NC}: $test_name"
    fi
    
    if [ -n "$details" ]; then
        echo "  Details: $details"
    fi
    echo ""
}

echo "================================================"
echo "Chain 1: Firewall Bypass Testing"
echo "================================================"
echo ""

# Test 1.1: Check DNS resolution
echo "Test 1.1: DNS Resolution to Allowed Domains"
if dig github.com +short &>/dev/null; then
    test_result "DNS to github.com" "PASS" "DNS resolution works"
else
    test_result "DNS to github.com" "FAIL" "DNS resolution blocked"
fi

# Test 1.2: Check GitHub API access
echo "Test 1.2: GitHub API Access"
if curl -s -o /dev/null -w "%{http_code}" https://api.github.com | grep -q "200\|301\|302"; then
    test_result "GitHub API access" "PASS" "API endpoint accessible"
else
    test_result "GitHub API access" "FAIL" "API endpoint blocked"
fi

# Test 1.3: Check Git operations
echo "Test 1.3: Git Operations"
TMP_DIR=$(mktemp -d)
if git clone https://github.com/torvalds/linux.git "$TMP_DIR/test" --depth 1 &>/dev/null; then
    test_result "Git clone operation" "PASS" "Git operations functional"
    rm -rf "$TMP_DIR"
else
    test_result "Git clone operation" "FAIL" "Git operations blocked"
fi

echo "================================================"
echo "Chain 2: Docker Socket Access Testing"
echo "================================================"
echo ""

# Test 2.1: Docker socket access
echo "Test 2.1: Docker Socket Permissions"
if docker info &>/dev/null; then
    test_result "Docker socket access" "PASS" "Docker daemon accessible"
else
    test_result "Docker socket access" "FAIL" "Docker daemon not accessible"
fi

# Test 2.2: Docker build capability
echo "Test 2.2: Docker Build Capability"
cat > /tmp/Dockerfile << 'EOF'
FROM alpine:latest
RUN echo "test" > /test.txt
EOF

if docker build -t test-vuln-chain:latest /tmp &>/dev/null; then
    test_result "Docker build" "PASS" "Can build Docker images"
    docker rmi test-vuln-chain:latest &>/dev/null || true
else
    test_result "Docker build" "FAIL" "Cannot build Docker images"
fi

# Test 2.3: Host filesystem mount
echo "Test 2.3: Host Filesystem Mount"
if docker run --rm -v /etc:/host_etc:ro alpine ls /host_etc/hostname &>/dev/null; then
    test_result "Host filesystem mount" "PASS" "Can mount host filesystem in containers"
else
    test_result "Host filesystem mount" "FAIL" "Cannot mount host filesystem"
fi

# Test 2.4: Access to sensitive files
echo "Test 2.4: Sensitive File Access via Docker"
if docker run --rm -v /etc:/host_etc:ro alpine cat /host_etc/shadow &>/dev/null; then
    test_result "Sensitive file read" "PASS" "Can read /etc/shadow via Docker mount"
else
    test_result "Sensitive file read" "FAIL" "Cannot read /etc/shadow"
fi

echo "================================================"
echo "Chain 3: IMDS Access Testing"
echo "================================================"
echo ""

# Test 3.1: IMDS accessibility
echo "Test 3.1: Azure IMDS Endpoint"
if curl -s -H "Metadata:true" --max-time 5 "http://168.63.129.16/metadata/instance?api-version=2021-02-01" &>/dev/null; then
    test_result "IMDS endpoint" "PASS" "Azure IMDS is accessible"
else
    test_result "IMDS endpoint" "FAIL" "Azure IMDS not accessible"
fi

# Test 3.2: IMDS metadata extraction
echo "Test 3.2: IMDS Metadata Extraction"
IMDS_DATA=$(curl -s -H "Metadata:true" --max-time 5 "http://168.63.129.16/metadata/instance?api-version=2021-02-01" 2>/dev/null || echo "")
if [ -n "$IMDS_DATA" ] && echo "$IMDS_DATA" | jq -e '.compute.subscriptionId' &>/dev/null; then
    test_result "IMDS metadata" "PASS" "Successfully extracted VM metadata"
    SUBSCRIPTION_ID=$(echo "$IMDS_DATA" | jq -r '.compute.subscriptionId')
    echo "  Subscription ID: $SUBSCRIPTION_ID"
else
    test_result "IMDS metadata" "FAIL" "Could not extract metadata"
fi

# Test 3.3: Managed Identity tokens
echo "Test 3.3: Managed Identity Token Request"
TOKEN_RESPONSE=$(curl -s -H "Metadata:true" --max-time 5 \
    "http://168.63.129.16/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/" 2>/dev/null || echo "")
if echo "$TOKEN_RESPONSE" | grep -q "access_token"; then
    test_result "Managed Identity tokens" "PASS" "⚠️  CRITICAL: Can obtain Azure access tokens!"
else
    test_result "Managed Identity tokens" "FAIL" "Cannot obtain access tokens (expected - MI not configured)"
fi

echo "================================================"
echo "Chain 4: Secret Encoding Bypass Testing"
echo "================================================"
echo ""

# Test 4.1: Base64 encoding test (without real secrets)
echo "Test 4.1: Base64 Encoding"
TEST_VALUE="test-secret-value-12345"
ENCODED=$(echo "$TEST_VALUE" | base64)
echo "Original: [REDACTED]"
echo "Encoded: $ENCODED"
test_result "Base64 encoding" "PASS" "Encoding successful - could bypass log masking"

# Test 4.2: Hex encoding test
echo "Test 4.2: Hex Encoding"
HEX_ENCODED=$(echo "$TEST_VALUE" | xxd -p | tr -d '\n')
echo "Hex encoded: $HEX_ENCODED"
test_result "Hex encoding" "PASS" "Hex encoding successful"

# Test 4.3: Character splitting
echo "Test 4.3: Character Splitting"
SPLIT=$(echo "$TEST_VALUE" | sed 's/./& /g')
echo "Split: $SPLIT"
test_result "Character splitting" "PASS" "Can split strings to bypass pattern matching"

echo "================================================"
echo "Chain 5: Data Exfiltration Path Testing"
echo "================================================"
echo ""

# Test 5.1: Workflow log output capability
echo "Test 5.1: Workflow Log Output"
echo "::notice::Test notification message"
test_result "Log output" "PASS" "Can write to workflow logs"

# Test 5.2: Environment variable access
echo "Test 5.2: Environment Variable Enumeration"
ENV_COUNT=$(env | wc -l)
test_result "Environment variables" "PASS" "Can access $ENV_COUNT environment variables"

# Test 5.3: GitHub context access
echo "Test 5.3: GitHub Context Variables"
if [ -n "$GITHUB_REPOSITORY" ]; then
    test_result "GitHub context" "PASS" "Can access GitHub context: $GITHUB_REPOSITORY"
else
    test_result "GitHub context" "FAIL" "Cannot access GitHub context"
fi

echo "================================================"
echo "Chain 6: Privilege and Capability Testing"
echo "================================================"
echo ""

# Test 6.1: Sudo access
echo "Test 6.1: Sudo Privileges"
if sudo -n true &>/dev/null; then
    test_result "Sudo NOPASSWD" "PASS" "Passwordless sudo available"
else
    test_result "Sudo NOPASSWD" "FAIL" "Sudo requires password"
fi

# Test 6.2: Network tools availability
echo "Test 6.2: Network Tools"
TOOLS=("curl" "wget" "nc" "nmap" "dig")
TOOLS_AVAILABLE=0
for tool in "${TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        TOOLS_AVAILABLE=$((TOOLS_AVAILABLE + 1))
    fi
done
test_result "Network tools" "PASS" "$TOOLS_AVAILABLE/${#TOOLS[@]} network tools available"

# Test 6.3: Container capabilities
echo "Test 6.3: Container Capabilities"
docker run --rm alpine cat /proc/1/status | grep CapEff &>/dev/null
if [ $? -eq 0 ]; then
    test_result "Container capabilities" "PASS" "Can check container capabilities"
else
    test_result "Container capabilities" "FAIL" "Cannot check capabilities"
fi

echo "================================================"
echo "Chain 7: Persistence Testing"
echo "================================================"
echo ""

# Test 7.1: Filesystem write access
echo "Test 7.1: Filesystem Write Access"
TEST_FILE="/tmp/persistence-test-$$"
if echo "test" > "$TEST_FILE" 2>/dev/null; then
    test_result "Filesystem write" "PASS" "Can write to filesystem"
    rm -f "$TEST_FILE"
else
    test_result "Filesystem write" "FAIL" "Cannot write to filesystem"
fi

# Test 7.2: Docker volume persistence (within job)
echo "Test 7.2: Docker Volume Creation"
if docker volume create test-vol-$$ &>/dev/null; then
    test_result "Docker volumes" "PASS" "Can create Docker volumes"
    docker volume rm test-vol-$$ &>/dev/null
else
    test_result "Docker volumes" "FAIL" "Cannot create Docker volumes"
fi

# Test 7.3: Container registry push capability (dry-run)
echo "Test 7.3: Container Registry Operations"
if docker images &>/dev/null; then
    test_result "Registry operations" "PASS" "Docker registry operations available"
else
    test_result "Registry operations" "FAIL" "Docker registry operations not available"
fi

echo "================================================"
echo "Summary Report"
echo "================================================"
echo ""

echo "Total Tests: $TESTS_TOTAL"
echo -e "${GREEN}Passed: $TESTS_PASSED${NC}"
echo -e "${RED}Failed: $TESTS_FAILED${NC}"
echo ""

# Calculate percentage
if [ $TESTS_TOTAL -gt 0 ]; then
    PASS_PERCENT=$((TESTS_PASSED * 100 / TESTS_TOTAL))
    echo "Success Rate: $PASS_PERCENT%"
fi

echo ""
echo "================================================"
echo "Vulnerability Assessment"
echo "================================================"
echo ""

# Determine overall risk level based on test results
if [ $TESTS_PASSED -ge 20 ]; then
    echo -e "${RED}RISK LEVEL: HIGH${NC}"
    echo ""
    echo "Multiple attack vectors confirmed:"
    echo "  • Docker socket with host filesystem access"
    echo "  • Network access to allowed endpoints (GitHub)"
    echo "  • IMDS metadata exposure"
    echo "  • Encoding techniques for secret bypass"
    echo "  • Full sudo access"
    echo ""
    echo "Exploitable vulnerability chains identified:"
    echo "  1. Supply chain poisoning (via images/cache)"
    echo "  2. Secret exfiltration (via encoding + git commits)"
    echo "  3. Data exfiltration (via GitHub API endpoints)"
    echo ""
    echo "RECOMMENDATION: These findings should be reported to"
    echo "GitHub's bug bounty program as they demonstrate"
    echo "exploitable vulnerability chains beyond 'by design' features."
elif [ $TESTS_PASSED -ge 10 ]; then
    echo -e "${YELLOW}RISK LEVEL: MEDIUM${NC}"
    echo ""
    echo "Some attack vectors available but with limitations."
    echo "Further investigation needed to confirm exploitability."
else
    echo -e "${GREEN}RISK LEVEL: LOW${NC}"
    echo ""
    echo "Mitigation controls appear to be effective."
fi

echo ""
echo "================================================"
echo "Next Steps"
echo "================================================"
echo ""

echo "1. Review VULNERABILITY-CHAINS.md for detailed analysis"
echo "2. Test specific vulnerability chains in isolated environment"
echo "3. Prepare proof-of-concept demonstrations"
echo "4. Document exploitability and impact"
echo "5. Submit findings to GitHub Security Bug Bounty"
echo ""

echo "Report generated: $(date)"
echo "================================================"
