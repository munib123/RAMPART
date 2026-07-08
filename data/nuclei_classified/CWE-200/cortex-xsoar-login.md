# Vulnerability: Cortex XSOAR Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cortex-xsoar-login.yaml`)

## Description
Cortex XSOAR login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/#/login
```

