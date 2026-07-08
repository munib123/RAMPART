# Vulnerability: BoltCMS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bolt-cms-panel.yaml`)

## Description
BoltCMS login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/bolt/login
```

