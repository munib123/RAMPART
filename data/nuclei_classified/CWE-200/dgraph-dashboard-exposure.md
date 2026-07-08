# Vulnerability: Dgraph Ratel Dashboard Exposure Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dgraph-dashboard-exposure.yaml`)

## Description
Dgraph Ratel Dashboard Exposure panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/?dev
```

