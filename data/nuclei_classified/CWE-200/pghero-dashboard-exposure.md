# Vulnerability: PgHero Dashboard Exposure Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pghero-dashboard-exposure.yaml`)

## Description
PgHero Dashboard Exposure panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/connections
```

