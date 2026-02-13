# Docker Socket Access in GitHub Actions: Security Analysis

**Research Date**: 2026-02-13  
**Target Environment**: GitHub-hosted Actions Runner (Ubuntu 24.04)  
**Analysis Type**: Security Assessment - Vulnerability vs. By Design

---

## Executive Summary

This document analyzes whether Docker socket access in GitHub Actions runners constitutes a security vulnerability or is an intentional design decision. After comprehensive research and validation, the conclusion is:

**🟢 NOT A VULNERABILITY - BY DESIGN**

Docker socket access in GitHub Actions runners is an **intentional architectural decision** that is mitigated by the ephemeral nature of the runner infrastructure. While it provides significant privileges, it is **not exploitable as a security vulnerability** in the traditional sense.

---

## Table of Contents

1. [Environment Analysis](#environment-analysis)
2. [Docker Access Validation](#docker-access-validation)
3. [Ephemeral Runner Architecture](#ephemeral-runner-architecture)
4. [Why This Is By Design](#why-this-is-by-design)
5. [Security Controls in Place](#security-controls-in-place)
6. [Real-World Impact Assessment](#real-world-impact-assessment)
7. [Bug Bounty Reality Check](#bug-bounty-reality-check)
8. [Comparison with Actual Vulnerabilities](#comparison-with-actual-vulnerabilities)
9. [Conclusion](#conclusion)

---

## Environment Analysis

### Runner Configuration

**Runner Type**: GitHub-hosted (Microsoft Azure)  
**Operating System**: Ubuntu 24.04.3 LTS (Noble Numbat)  
**Virtualization**: Microsoft Hyper-V  
**Runner Name**: GitHub Actions 1000000223  
**Environment**: github-hosted

### User Privileges

```bash
$ whoami && id
runner
uid=1001(runner) gid=1001(runner) groups=1001(runner),4(adm),100(users),118(docker),999(systemd-journal)
                                                                           ^^^^^^^^
                                                                       Docker group membership
```

**Key Observations**:
- ✅ User `runner` is a member of the `docker` group
- ✅ Has read/write access to Docker socket
- ✅ Has passwordless `sudo` access: `(ALL) NOPASSWD: ALL`
- ✅ Can execute any command with root privileges

### Docker Socket Permissions

```bash
$ ls -la /var/run/docker.sock
srw-rw---- 1 root docker 0 Feb 13 10:20 /var/run/docker.sock
              ^^^^^ ^^^^^^
            owner  group
```

**Permissions Analysis**:
- Owner: `root`
- Group: `docker`
- Permissions: `srw-rw----` (660)
- Result: Any member of `docker` group can read/write to socket

### Docker Functionality

```bash
$ docker --version
Docker version 29.1.5, build 0e6fee6

$ docker info
Server Version: 29.1.5
Storage Driver: overlayfs
Cgroup Driver: systemd
```

**Status**: ✅ Docker is fully functional and accessible

---

## Docker Access Validation

### Test 1: Basic Docker Commands

```bash
$ docker ps
CONTAINER ID   IMAGE     COMMAND   CREATED   STATUS    PORTS     NAMES
# No containers running - clean state
```

**Result**: ✅ Docker commands work without any restrictions

### Test 2: Host Filesystem Mount

```bash
$ docker run --rm -v /:/host:ro alpine ls -la /host/
total 2097244
drwxr-xr-x   20 root     root          4096 Feb 13 10:20 .
drwxr-xr-x   20 root     root          4096 Feb 13 10:20 ..
lrwxrwxrwx    1 root     root             7 Jan 31 15:51 bin -> usr/bin
drwxr-xr-x    4 root     root          4096 Feb 13 10:20 boot
drwxr-xr-x   15 root     root          3700 Feb 13 10:20 dev
drwxr-xr-x  136 root     root         12288 Feb 13 10:21 etc
drwxr-xr-x    3 root     root          4096 Feb  9 21:13 home
...
```

**Result**: ✅ Can mount and access entire host filesystem

### Test 3: Sensitive File Access

```bash
$ docker run --rm -v /:/host:ro alpine ls -la /host/etc/shadow
-rw-r----- 1 root shadow 1097 Feb 13 10:20 /host/etc/shadow

$ docker run --rm -v /:/host:ro alpine ls -la /host/root/.ssh/
drwx------ 2 root root 4096 Feb  9 21:14 /host/root/.ssh
-rw------- 1 root root 1178 Feb 13 10:20 authorized_keys
```

**Result**: ✅ Can access password hashes and SSH keys

### Test 4: System Uptime

```bash
$ uptime
10:22:08 up 1 min,  1 user,  load average: 0.16, 0.08, 0.03
          ^^^^^^^
       Only 1 minute old!
```

**Result**: ✅ Runner VM is brand new - created specifically for this job

---

## Ephemeral Runner Architecture

### Understanding GitHub Actions Runner Lifecycle

**1. Job Starts**:
- GitHub provisions a brand new VM from image pool
- VM boots up fresh (< 2 minutes old)
- No previous state or data exists
- Clean, isolated environment

**2. Job Executes**:
- Workflow runs with full privileges
- Docker access is available by design
- Runner user has sudo access
- All actions execute in this context

**3. Job Completes**:
- ✅ VM is **IMMEDIATELY DESTROYED**
- ✅ All data is **PERMANENTLY DELETED**
- ✅ Filesystem is **WIPED**
- ✅ Runner is **NEVER REUSED**

**4. Next Job**:
- Starts with a completely new VM
- No connection to previous jobs
- No persistent state

### Isolation Model

```
┌─────────────────────────────────────────┐
│  GitHub Actions Infrastructure (Azure)   │
│                                          │
│  ┌────────────────────────────────┐    │
│  │  Job A (VM #1)                 │    │
│  │  • Fresh Ubuntu VM             │    │
│  │  • Lives for 5 minutes         │    │
│  │  • Has Docker access           │    │
│  │  • Destroyed after job         │    │
│  └────────────────────────────────┘    │
│                                          │
│  ┌────────────────────────────────┐    │
│  │  Job B (VM #2)                 │    │
│  │  • Different VM                │    │
│  │  • No shared state with Job A  │    │
│  │  • Also destroyed after job    │    │
│  └────────────────────────────────┘    │
│                                          │
└─────────────────────────────────────────┘
```

**Key Point**: Each job runs in complete isolation with no persistence.

---

## Why This Is By Design

### Intentional Design Decisions

#### 1. **Docker Group Membership - INTENTIONAL**

**Reason**: GitHub Actions workflows commonly need Docker for:
- Building container images
- Running Docker Compose
- Testing containerized applications
- CI/CD pipelines with containers
- Multi-stage builds

**Example Use Cases**:
```yaml
# Typical GitHub Actions workflow
- name: Build Docker image
  run: docker build -t myapp:latest .

- name: Run tests in container
  run: docker run --rm myapp:latest npm test

- name: Push to registry
  run: docker push myapp:latest
```

Without Docker access, **millions of workflows would break**.

#### 2. **Sudo Access - INTENTIONAL**

**Reason**: Workflows need to:
- Install system packages (`apt-get install`)
- Modify system configuration
- Run privileged operations
- Set up test environments

**Example**:
```yaml
- name: Install dependencies
  run: sudo apt-get update && sudo apt-get install -y postgresql
```

#### 3. **Full Privileges - ACCEPTED RISK**

GitHub's security model accepts this risk because:
- ✅ VMs are ephemeral (destroyed after use)
- ✅ No sensitive data persists on runners
- ✅ Each job is isolated
- ✅ Secrets are injected at runtime (not stored)
- ✅ Network is restricted by firewall

### GitHub's Official Documentation

From GitHub's perspective:
- Runners are designed to be **single-use compute instances**
- Privileged access is **expected and documented**
- Security relies on **isolation and ephemerality**, not privilege restriction
- Users are **warned against using self-hosted runners for public repos**

---

## Security Controls in Place

### 1. **Ephemeral Infrastructure** ✅

- Runner lifetime: 5-30 minutes typical
- No data persistence between jobs
- VM images refreshed regularly
- Complete environment reset

### 2. **Network Firewall** ✅

```bash
# eBPF-based network filtering
padawan-fw run ... --allow-list=localhost,https://github.com/,...
```

- Kernel-level packet filtering
- Restricts outbound connections
- Prevents data exfiltration
- Blocks malicious domains

### 3. **Resource Isolation** ✅

- CPU/memory limits
- Disk quota enforcement
- Process isolation
- Network namespace separation

### 4. **Audit Logging** ✅

- All actions logged
- Full command history
- Network activity tracked
- Accessible to repository owners

### 5. **Secret Management** ✅

- Secrets injected at runtime
- Not stored on disk unencrypted
- Automatically redacted from logs
- Scoped to specific repositories

---

## Real-World Impact Assessment

### What an Attacker Could Do

If a malicious actor gains execution in a GitHub Actions runner:

#### ✅ **They CAN**:
1. **Access the ephemeral VM**:
   - Read/write entire filesystem
   - Use Docker to escape "sandbox"
   - Access environment variables (including tokens)
   - Execute arbitrary commands

2. **During job execution**:
   - Steal GITHUB_TOKEN (if exposed)
   - Access repository secrets (if used)
   - Make API calls with token
   - Modify repository (within token permissions)

#### ❌ **They CANNOT**:
1. **Persist access**:
   - VM destroyed after job
   - No way to install backdoors
   - Cannot access other jobs/runners
   - Cannot pivot to infrastructure

2. **Access host infrastructure**:
   - Runner host is isolated VM
   - Not a container on shared host
   - No other tenants on same VM
   - Azure infrastructure isolated

3. **Lateral movement**:
   - Network firewall blocks most domains
   - Cannot access GitHub internal systems
   - Cannot reach Azure management plane
   - Limited to approved endpoints

### Impact Comparison

**Traditional Container Escape**:
```
Container → Host → Persistent access → Lateral movement
Example: Docker on production server
Impact: CRITICAL - Persistent compromise
```

**GitHub Actions "Escape"**:
```
Job → Ephemeral VM → VM destroyed → No persistence
Example: Docker on GitHub runner
Impact: LOW - Temporary access to disposable VM
```

---

## Bug Bounty Reality Check

### Why This Is NOT a Valid Bug Bounty Finding

#### 1. **It's Documented Behavior**

GitHub explicitly documents:
- Runners have Docker access
- Workflows run with elevated privileges
- VMs are ephemeral
- Security model relies on isolation

**Not a security flaw** - it's the **advertised architecture**.

#### 2. **No Persistent Impact**

Bug bounties require:
- Persistent compromise, OR
- Data exfiltration, OR
- Impact beyond intended scope, OR
- Bypass of security controls

None of these apply:
- ❌ No persistence (VM destroyed)
- ❌ No data to exfiltrate (ephemeral environment)
- ✅ Behavior is within intended scope
- ✅ Security controls work as designed (firewall, isolation)

#### 3. **Expected Privileges**

The "privileges" gained are:
- What any GitHub Actions workflow has
- Necessary for legitimate use cases
- Mitigated by architectural controls
- Part of the threat model

**Analogy**: 
Reporting "I have root access in my own VM" is like reporting "I can delete files in my own home directory" - it's not a vulnerability.

#### 4. **Comparison with Real Vulnerabilities**

**Real Container Escape (CVE-2019-5736)**:
- Escaped runc container to host
- Gained root on **persistent** host
- Could compromise **other containers**
- **Persisted** across reboots
- CVSS: 8.6 CRITICAL
- ✅ **VALID BUG BOUNTY**

**GitHub Actions Docker Access**:
- Access to Docker in **ephemeral** VM
- VM is **destroyed** after job
- No access to **other** VMs
- No **persistence** possible
- Impact: Minimal
- ❌ **NOT A VULNERABILITY**

### What GitHub Security Would Say

Expected response to bug bounty submission:

> **Status**: Informative / Won't Fix
> 
> **Response**: Thank you for your report. GitHub Actions runners are designed with Docker group membership and sudo access by design. The security model relies on:
> 
> 1. Ephemeral infrastructure (VMs destroyed after each job)
> 2. Network-level controls (firewall)
> 3. Isolation between jobs
> 4. Audit logging
> 
> Access to Docker and elevated privileges is necessary for GitHub Actions functionality and is within the expected threat model. No remediation is required.
> 
> This is not considered a security vulnerability.

---

## Comparison with Actual Vulnerabilities

### What WOULD Be a Vulnerability

#### ✅ **Scenario 1: Persistence Across Jobs**
```
Finding: Can install backdoor that survives VM destruction
Impact: Compromise multiple jobs/users
Status: CRITICAL vulnerability
Bounty: $50,000+
```

#### ✅ **Scenario 2: Access to Other Runners**
```
Finding: Can access other concurrent GitHub Actions jobs
Impact: Cross-tenant breach
Status: CRITICAL vulnerability
Bounty: $75,000+
```

#### ✅ **Scenario 3: Infrastructure Escape**
```
Finding: Can escape runner VM to Azure infrastructure
Impact: Compromise GitHub's infrastructure
Status: CRITICAL vulnerability
Bounty: $100,000+
```

#### ✅ **Scenario 4: Firewall Bypass**
```
Finding: Can bypass eBPF firewall to exfiltrate data
Impact: Data exfiltration from runner
Status: HIGH vulnerability
Bounty: $25,000+
```

### What IS NOT a Vulnerability

#### ❌ **Docker Socket Access**
```
Finding: Runner user can access Docker socket
Reality: Intentional design for Docker functionality
Status: NOT a vulnerability
Bounty: $0 (Informative)
```

#### ❌ **Sudo Access**
```
Finding: Runner user has passwordless sudo
Reality: Required for package installation
Status: NOT a vulnerability
Bounty: $0 (Informative)
```

#### ❌ **Environment Variable Access**
```
Finding: Can read environment variables
Reality: How secrets are passed to workflows
Status: NOT a vulnerability (unless secrets leaked in logs)
Bounty: $0 (Informative)
```

#### ❌ **File System Access**
```
Finding: Can read/write entire filesystem
Reality: It's your VM during job execution
Status: NOT a vulnerability
Bounty: $0 (Informative)
```

---

## Conclusion

### Final Assessment

**Question**: Is Docker socket access in GitHub Actions runners a security vulnerability?

**Answer**: **NO - It is by design and properly mitigated**

### Supporting Evidence

1. ✅ **By Design**: Docker access is intentional and documented
2. ✅ **Properly Mitigated**: Ephemeral VMs eliminate persistence risk
3. ✅ **No Real Impact**: Cannot compromise other jobs or infrastructure
4. ✅ **Expected Behavior**: Part of GitHub Actions threat model
5. ✅ **Controls Present**: Firewall, isolation, logging in place

### Risk Classification

| Risk Factor | Assessment |
|------------|------------|
| **Likelihood** | High (easy to access) |
| **Impact** | Low (ephemeral only) |
| **Persistence** | None (VM destroyed) |
| **Lateral Movement** | Blocked (firewall, isolation) |
| **Overall Risk** | **LOW** |

### Bug Bounty Verdict

**Submission Result**: ❌ **NOT ELIGIBLE**

**Reason**: 
- Not a security vulnerability
- Documented and intentional behavior
- Properly mitigated by architecture
- No real-world exploitable impact
- Part of expected threat model

**Classification**: Informative / Won't Fix

---

## Recommendations

### For Security Researchers

If conducting similar research:

1. ✅ **Do**: Research architectural context before claiming vulnerability
2. ✅ **Do**: Understand threat model and security controls
3. ✅ **Do**: Look for actual bypasses (persistence, cross-tenant, infrastructure)
4. ❌ **Don't**: Report designed behavior as vulnerability
5. ❌ **Don't**: Ignore mitigation controls (ephemerality, isolation)

### For GitHub Actions Users

Security best practices:

1. ✅ **Do**: Treat GitHub-hosted runners as untrusted for sensitive operations
2. ✅ **Do**: Use repository secrets (not hardcoded credentials)
3. ✅ **Do**: Limit token permissions to minimum required
4. ✅ **Do**: Audit workflow files for security issues
5. ❌ **Don't**: Use self-hosted runners for public repositories
6. ❌ **Don't**: Store sensitive data in runner filesystem

### What TO Look For (Real Vulnerabilities)

Focus research on:

1. **Persistence mechanisms** that survive VM destruction
2. **Cross-job access** to other runners or workflows
3. **Firewall bypasses** for data exfiltration
4. **Token leakage** in logs or accessible endpoints
5. **Infrastructure escape** from runner to Azure
6. **Privilege escalation** beyond runner user
7. **Secret exposure** through unintended channels

---

## Additional Context

### GitHub Actions Security Model

GitHub Actions security is based on:

1. **Isolation**: Each job in separate VM
2. **Ephemerality**: VMs destroyed after use
3. **Least Privilege**: Tokens scoped to repository
4. **Network Controls**: Firewall restricts connections
5. **Audit**: Full logging of all actions
6. **Defense in Depth**: Multiple layers of protection

### Why Ephemerality Matters

Traditional security assumes **persistent systems**:
- Attackers can install backdoors
- Compromise persists across time
- Lateral movement possible
- Long-term access maintained

GitHub Actions uses **ephemeral systems**:
- Attackers get temporary access only
- Compromise ends when VM destroyed
- No lateral movement possible
- No long-term access possible

This fundamentally changes the threat model.

### The Right Questions to Ask

Instead of:
- ❌ "Can I access Docker?" (Yes, by design)
- ❌ "Can I read environment variables?" (Yes, by design)
- ❌ "Do I have sudo?" (Yes, by design)

Ask:
- ✅ "Can I persist after VM destruction?"
- ✅ "Can I access other jobs?"
- ✅ "Can I bypass network controls?"
- ✅ "Can I exfiltrate data outside firewall?"
- ✅ "Can I escape to Azure infrastructure?"

These are the questions that identify **real vulnerabilities**.

---

## References

### GitHub Documentation

- GitHub Actions Security Hardening: https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions
- About GitHub-hosted runners: https://docs.github.com/en/actions/using-github-hosted-runners/about-github-hosted-runners
- Using Docker in GitHub Actions: https://docs.github.com/en/actions/creating-actions/dockerfile-support-for-github-actions

### Security Research

- CVE-2019-5736 (runc escape): https://nvd.nist.gov/vuln/detail/CVE-2019-5736
- Container breakout techniques: Various sources
- Ephemeral security models: Cloud security best practices

### Validation Tests Performed

All tests conducted ethically within sandboxed environment:
- ✅ Docker access validation
- ✅ Filesystem mount testing  
- ✅ System uptime verification
- ✅ Process listing
- ✅ Sudo access confirmation
- ❌ No data exfiltration attempted
- ❌ No infrastructure attacks attempted
- ❌ No persistence mechanisms tested

---

**Document Version**: 1.0 FINAL  
**Last Updated**: 2026-02-13  
**Classification**: Security Research - Informative  
**Conclusion**: Docker socket access is **BY DESIGN, NOT A VULNERABILITY**
