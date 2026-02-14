# Security Testing Evidence

This directory contains the actual test scripts and evidence from manual security validation.

## Test Scripts

All scripts can be re-run to verify findings:

- `test_info_disclosure.sh` - Tests /tools endpoint exposure (VERIFIED vulnerability)
- `test_direct_invocation.sh` - Tests direct tool invocation (NOT vulnerable)
- `test_process_access.sh` - Tests process and stdio access
- `test_race_condition.sh` - Tests race condition exploit (NOT vulnerable)
- `test_network_enum.sh` - Tests network connectivity and restrictions

## Evidence Files

- `browser_evaluate_schema.json` - Extracted tool schema showing information disclosure

## Running Tests

```bash
cd evidence
chmod +x *.sh
./test_info_disclosure.sh
./test_direct_invocation.sh
./test_race_condition.sh
```

All tests were executed in a live GitHub Actions environment with actual MCP server running.
