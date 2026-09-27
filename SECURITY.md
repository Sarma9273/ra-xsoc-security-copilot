# Security Policy — RA-XSOC-X

## Scope

RA-XSOC-X is an AI-assisted security investigation system. The public GitHub Pages demo is synthetic and read-only.

## Security boundaries

- No autonomous containment, blocking, deletion, or command execution.
- No production credentials or private SOC data belong in the repository.
- Analyst-facing recommendations require human review.
- MITRE ATT&CK mappings are treated as knowledge references, not proof of an incident.
- Generated ML artifacts are rebuilt from the versioned corpus rather than trusted blindly.

## Reporting

Do not publish exploitable vulnerabilities in public issues. Report security problems privately to the repository owner.

## Data handling

Do not commit secrets, API tokens, production logs, customer data, PCAPs containing sensitive information, or credentials.

## Release gates

A release requires passing frontend build/lint, Python tests, retrieval artifact generation, static security checks, and reproducible benchmark evaluation.
