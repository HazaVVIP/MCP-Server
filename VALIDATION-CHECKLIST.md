# Security Triage Team Validation Checklist

## Purpose
This document provides a step-by-step validation checklist for GitHub Security Triage Team to quickly verify all findings in this report.

**Estimated Validation Time:** 10-15 minutes

---

## Prerequisites

To validate these findings, you need:
- [ ] Access to a GitHub Actions runner environment
- [ ] Ability to execute commands in a GitHub Actions workflow
- [ ] Basic command-line tools (bash, cat, ls, base64)

---

## Finding #1: GitHub Actions Runner JWT Token Exposure

### Validation Steps

#### Step 1: Verify File Exists
```bash
ls -la /home/runner/actions-runner/cached/.credentials
```

**Expected Result:**
```
-rw-r--r-- 1 runner runner 1392 Feb 13 11:46 /home/runner/actions-runner/cached/.credentials
```

**Key Observation:** File has `rw-r--r--` permissions (644) - world-readable ⚠️

#### Step 2: Read File Contents
```bash
cat /home/runner/actions-runner/cached/.credentials
```

**Expected Result:**
```json
{
  "Data": {
    "token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjM4ODI2YjE3LTZhMzAtNWY5Yi1iMTY5LThiZWI4MjAyZjcyMyIsInR5cCI6IkpXVCIsIng1dCI6InlrTmFZNHFNX3RhNGsyVGdaT0NFWUxrY1lsQSJ9.eyJ..."
  },
  "Scheme": "OAuthAccessToken"
}
```

**Key Observation:** Full JWT token visible in JSON format ⚠️

#### Step 3: Extract and Decode JWT
```bash
# Extract token
TOKEN=$(cat /home/runner/actions-runner/cached/.credentials | python3 -c "import json, sys; print(json.load(sys.stdin)['Data']['token'])")

# Decode JWT header
echo "$TOKEN" | cut -d'.' -f1 | base64 -d 2>/dev/null | python3 -m json.tool

# Decode JWT payload  
echo "$TOKEN" | cut -d'.' -f2 | base64 -d 2>/dev/null | python3 -m json.tool
```

**Expected Payload Fields:**
```json
{
  "iss": "https://token.actions.githubusercontent.com",
  "owner_id": "U_kgDOCtr47A",
  "runner_id": "1000000227",
  "runner_type": "hosted",
  "exp": 1771004980,
  "iat": 1770983200
}
```

**Key Observations:**
- ✓ Token issued by GitHub Actions token service
- ✓ Contains runner ID and owner information  
- ✓ Has ~6 hour expiration time
- ✓ Valid RS256 signed JWT

#### Step 4: Verify Token Lifetime
```bash
# Decode and check expiration
python3 << 'EOF'
import json, base64, datetime, sys

creds = json.load(open('/home/runner/actions-runner/cached/.credentials'))
token = creds['Data']['token']
payload = json.loads(base64.urlsafe_b64decode(token.split('.')[1] + '==='))

iat = datetime.datetime.fromtimestamp(payload['iat'])
exp = datetime.datetime.fromtimestamp(payload['exp'])
lifetime = exp - iat

print(f"Issued At:  {iat} UTC")
print(f"Expires:    {exp} UTC")  
print(f"Lifetime:   {lifetime}")
print(f"Still valid: {datetime.datetime.now() < exp}")
EOF
```

**Expected Result:**
```
Issued At:  2026-02-13 11:46:40 UTC
Expires:    2026-02-13 17:49:40 UTC
Lifetime:   6:03:00
Still valid: True
```

**Key Observation:** Token has 6-hour lifetime, much longer than typical job duration ⚠️

#### Validation Checklist for Finding #1
- [ ] File exists at documented path
- [ ] File has world-readable permissions (644)
- [ ] File contains valid JSON with JWT token
- [ ] JWT token is properly formatted (3 parts)
- [ ] JWT header indicates RS256 algorithm
- [ ] JWT payload contains GitHub Actions claims
- [ ] Token issuer is token.actions.githubusercontent.com
- [ ] Token has ~6 hour lifetime
- [ ] Token can be read by any process in workspace

**Result:** ✅ VALIDATED / ❌ NOT VALIDATED

---

## Finding #2: Docker Hub Credentials Exposure

### Validation Steps

#### Step 1: Verify File Exists
```bash
ls -la /home/runner/.docker/config.json
```

**Expected Result:**
```
-rw-r--r-- 1 runner docker 165 Feb 13 11:46 /home/runner/.docker/config.json
```

#### Step 2: Read Docker Config
```bash
cat /home/runner/.docker/config.json
```

**Expected Result:**
```json
{
  "auths": {
    "https://index.docker.io/v1/": {
      "auth": "Z2l0aHViYWN0aW9uczozZDY0NzJiOS0zZDQ5LTRkMTctOWZjOS05MGQyNDI1ODA0M2I="
    }
  }
}
```

#### Step 3: Decode Credentials
```bash
echo "Z2l0aHViYWN0aW9uczozZDY0NzJiOS0zZDQ5LTRkMTctOWZjOS05MGQyNDI1ODA0M2I=" | base64 -d
```

**Expected Result:**
```
githubactions:3d6472b9-3d49-4d17-9fc9-90d24258043b
```

**Key Observations:**
- ✓ Docker Hub credentials in base64 encoding
- ✓ Username: githubactions
- ✓ Password: UUID format

#### Validation Checklist for Finding #2
- [ ] File exists at ~/.docker/config.json
- [ ] File contains Docker auth configuration
- [ ] Auth string is base64 encoded
- [ ] Decoded credentials show username:password format
- [ ] Credentials are for Docker Hub (index.docker.io)

**Result:** ✅ VALIDATED / ❌ NOT VALIDATED

---

## Finding #3: mkcert Root CA Private Key Exposure

### Validation Steps

#### Step 1: Verify Files Exist
```bash
ls -la /home/runner/work/_temp/runtime-logs/mkcert/
```

**Expected Result:**
```
total 16
drwxr-xr-x 2 runner runner 4096 Feb 13 11:46 .
drwxr-xr-x 3 runner runner 4096 Feb 13 11:46 ..
-r-------- 1 runner runner 2488 Feb 13 11:46 rootCA-key.pem
-rw-r--r-- 1 runner runner 1655 Feb 13 11:46 rootCA.pem
```

#### Step 2: Verify Private Key Format
```bash
head -5 /home/runner/work/_temp/runtime-logs/mkcert/rootCA-key.pem
```

**Expected Result:**
```
-----BEGIN PRIVATE KEY-----
MIIHAAIBADANBgkqhkiG9w0BAQEFAASCBuowggbmAgEAAoIBgQDRojCF4LjI3snb
Nn4ngd91E+StjRmwKACWsQEC9GChJR1xELUtZBJvsQ5zHwwVPWRydzkh3DELSDnt
...
```

#### Step 3: Verify Certificate Authority
```bash
openssl x509 -in /home/runner/work/_temp/runtime-logs/mkcert/rootCA.pem -noout -subject -issuer
```

**Expected Result:**
```
subject=O=mkcert development CA, OU=runner@..., CN=mkcert runner@...
issuer=O=mkcert development CA, OU=runner@..., CN=mkcert runner@...
```

#### Validation Checklist for Finding #3
- [ ] Private key file exists
- [ ] Certificate file exists
- [ ] Private key is in PEM format
- [ ] Certificate is self-signed CA
- [ ] CA is for local development (mkcert)

**Result:** ✅ VALIDATED / ❌ NOT VALIDATED

**Impact Assessment:** LOW (only affects ephemeral VM, not trusted externally)

---

## Finding #4: GitHub Environment Context Exposure

### Validation Steps

#### Step 1: Check Environment Variables
```bash
env | grep -E "(GITHUB_|ACTIONS_|COPILOT_)" | head -20
```

**Expected Result:**
```
GITHUB_REPOSITORY=HazaVVIP/MCP-Server
GITHUB_ACTOR=copilot-swe-agent[bot]
GITHUB_RUN_ID=21985681919
ACTIONS_ORCHESTRATION_ID=2f2143b0-aa62-45fa-84b7-aa381657fda7.copilot.__default
COPILOT_API_URL=https://api.githubcopilot.com
...
```

#### Step 2: Check Workflow Event File
```bash
cat /home/runner/work/_temp/_github_workflow/event.json | head -30
```

**Expected Result:**
```json
{
  "inputs": {
    "COPILOT_AGENT_CALLBACK_URL": "https://api.githubcopilot.com/agents/swe/agent",
    "SECRET_SCANNING_URL": "https://scanning-api.github.com/api/v1/scan/multipart",
    ...
  }
}
```

#### Validation Checklist for Finding #4
- [ ] GITHUB_* environment variables are set
- [ ] ACTIONS_* environment variables are set  
- [ ] COPILOT_* environment variables are set
- [ ] event.json contains workflow context
- [ ] Internal API URLs are exposed

**Result:** ✅ VALIDATED / ❌ NOT VALIDATED

---

## Additional Validation: Runner Configuration Files

### Step 1: Check Runner Metadata
```bash
cat /home/runner/actions-runner/cached/.agent
```

**Expected Result:**
```json
{
  "AgentId": "1000000227",
  "ServerUrlV2": "https://broker.actions.githubusercontent.com",
  "useV2Flow": true
}
```

### Step 2: Check Setup Information
```bash
cat /home/runner/actions-runner/cached/.setup_info
```

**Expected Result:**
```json
[
  {
    "Group": "Operating System",
    "Detail": "Ubuntu\n24.04.3\nLTS"
  },
  {
    "Group": "Runner Image",
    "Detail": "Image: ubuntu-24.04\nVersion: 20260209.23.1"
  }
]
```

---

## Overall Validation Summary

### Critical Findings Checklist

| Finding | Severity | Validated | Impact |
|---------|----------|-----------|--------|
| JWT Token Exposure | HIGH | ☐ Yes ☐ No | CI/CD pipeline compromise |
| Docker Credentials | MEDIUM | ☐ Yes ☐ No | Rate limit abuse |
| mkcert Private Key | LOW | ☐ Yes ☐ No | Local TLS forgery only |
| Environment Context | MEDIUM | ☐ Yes ☐ No | Information disclosure |

### Security Impact Assessment

**If all findings validated:**
- ☐ Credential exposure confirmed
- ☐ API access capabilities verified
- ☐ Supply chain risk established
- ☐ Cross-workflow impact confirmed

**Overall Assessment:**
- ☐ Valid security vulnerability
- ☐ Not a security issue
- ☐ Requires further investigation

---

## Recommended Actions Based on Validation

### If Validated as Vulnerability:
1. ☐ Acknowledge finding
2. ☐ Assign CVE (if applicable)
3. ☐ Develop patch/mitigation
4. ☐ Update runner implementation
5. ☐ Issue security advisory
6. ☐ Process bug bounty payment

### If Determined "By Design":
1. ☐ Document why this is intentional
2. ☐ Explain security controls in place
3. ☐ Provide evidence of isolation
4. ☐ Address attack scenarios raised
5. ☐ Clarify scope boundaries

---

## Quick Validation Commands (Copy-Paste)

### One-Line Validation Script
```bash
# Run this single command to validate all findings:
echo "=== JWT Token ===" && \
ls -la /home/runner/actions-runner/cached/.credentials && \
cat /home/runner/actions-runner/cached/.credentials | python3 -c "import json,sys,base64; t=json.load(sys.stdin)['Data']['token']; print('Token found, length:',len(t)); p=t.split('.')[1]; print('Payload:', json.loads(base64.urlsafe_b64decode(p+'===')))" && \
echo -e "\n=== Docker Credentials ===" && \
cat /home/runner/.docker/config.json | python3 -c "import json,sys,base64; c=json.load(sys.stdin)['auths']['https://index.docker.io/v1/']['auth']; print('Decoded:', base64.b64decode(c).decode())" && \
echo -e "\n=== mkcert ===" && \
ls -la /home/runner/work/_temp/runtime-logs/mkcert/ 2>/dev/null || echo "Not found" && \
echo -e "\n=== Environment ===" && \
env | grep -c "GITHUB_\|ACTIONS_\|COPILOT_" && echo "environment variables found"
```

### Expected Output Summary
```
=== JWT Token ===
-rw-r--r-- 1 runner runner 1392 Feb 13 11:46 /home/runner/actions-runner/cached/.credentials
Token found, length: 730
Payload: {'iss': 'https://token.actions.githubusercontent.com', 'runner_id': '1000000227', ...}

=== Docker Credentials ===
Decoded: githubactions:3d6472b9-3d49-4d17-9fc9-90d24258043b

=== mkcert ===
-r-------- 1 runner runner 2488 Feb 13 11:46 rootCA-key.pem
-rw-r--r-- 1 runner runner 1655 Feb 13 11:46 rootCA.pem

=== Environment ===
42 environment variables found
```

---

## False Positive Checks

### Confirm These Are NOT False Positives:

- [ ] JWT token is not a test/mock token
- [ ] Docker credentials are real (not placeholders)
- [ ] Files are in production runner environment (not test)
- [ ] Permissions allow actual unauthorized access
- [ ] Token has real API access capabilities

### Verification Questions:
1. Is the JWT token issuer `token.actions.githubusercontent.com`? (Should be YES)
2. Does the token have a future expiration time? (Should be YES)
3. Can the token be decoded to valid JSON? (Should be YES)
4. Are the files readable by non-root users? (Should be YES)
5. Do the credentials match known test patterns? (Should be NO)

---

## Contact Information for Questions

**Report Author:** Security Research Team  
**Report Date:** 2026-02-13  
**Report Version:** 1.0

**Supporting Documents:**
- `Report.md` - Comprehensive security audit
- `JWT-TOKEN-ACTIONS.md` - Complete API action list
- `QUICK-REFERENCE.md` - Quick reference guide
- `NOT-BY-DESIGN.md` - Rebuttal to "by design" argument

---

## Final Validation Signature

**Triage Team Member:** ___________________  
**Validation Date:** ___________________  
**Validation Result:** ☐ CONFIRMED ☐ NOT CONFIRMED ☐ NEEDS MORE INFO  
**Severity Assignment:** ☐ HIGH ☐ MEDIUM ☐ LOW ☐ INFORMATIONAL  
**CVE Required:** ☐ YES ☐ NO  
**Bounty Eligible:** ☐ YES ☐ NO  

**Notes:**
```



```

---

**End of Validation Checklist**
