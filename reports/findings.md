# Security Findings Register

## Assessment context
All findings below were generated from synthetic demonstration data.
They must not be represented as confirmed production vulnerabilities.

| ID | Category | Severity | Status | Recommended action |
|---|---|---|---|---|
| TM-DEMO-API-01-02 | Authentication | HIGH | FAIL | Verify public exposure and enforce appropriate authentication. |
| TM-DEMO-SVC-02-01 | Architecture visibility | MEDIUM | REVIEW | Establish network reachability and trust boundaries. |
| DEP-0001 | Dependency | MEDIUM | REVIEW | Pin the dependency version and inspect the dependency tree. |
| API-0001 | API Security | HIGH | FAIL | Verify credential enforcement and add a regression test. |
| API-0002 | API Security | INFO | PASS | Retain the denial test and expand authorization coverage. |
| API-0003 | API Security | MEDIUM | REVIEW | Execute the expired-credential test and capture evidence. |

## Evidence requirements for closure
- Record the target, test conditions, timestamp, and tool/version information.
- Preserve sanitized request/response evidence where applicable.
- Confirm the expected policy with the system owner.
- Re-test the fix and record the regression result.
- Do not mark a finding verified without supporting evidence.
