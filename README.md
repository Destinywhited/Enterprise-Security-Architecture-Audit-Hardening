# Enterprise Security Architecture Audit & Hardening

A Python-based framework for evaluating enterprise security architecture,
threat exposure, software dependencies, API authentication, and remediation.

## Workstreams
- Threat modeling and attack-surface review
- Dependency and software supply-chain verification
- API authentication and authorization security checks
- Finding classification and remediation tracking
- Automated testing and reproducible evidence

## Project structure
- src/: audit engine and security assessment modules
- tests/: automated unit and regression tests
- data/: assessment inputs and test cases
- reports/: findings, methodology, and evaluation reports
- output/: generated machine-readable results
- docs/: scope and acceptance criteria

## Execution
Run the test suite from the project root:

    python -m unittest discover -s tests -v

The framework will distinguish verified checks, failed checks, and
inconclusive checks. Actual security conclusions require appropriate
target configurations, evidence, and authorized test access.
