# Vulnerability: Grafana Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`grafana-detect.yaml`)

## Description
Grafana login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
GET {{BaseURL}}/graph/login
```

