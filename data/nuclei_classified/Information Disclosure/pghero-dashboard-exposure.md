# Nuclei Template: PgHero Dashboard Exposure Panel - Detect
**Template ID:** pghero-dashboard-exposure
**Vulnerability Class:** Information Disclosure
**Severity:** Medium
**CWE:** CWE-200
**Source:** Nuclei Template (`pghero-dashboard-exposure.yaml`)

## Vulnerability Information & PoC

## Description
PgHero Dashboard Exposure panel was detected.

## Steps to reproduce / Exploit Payload
```http
GET {{BaseURL}}/connections
```

## References
- https://github.com/ankane/pghero
