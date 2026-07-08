# Vulnerability: ESXi System Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`esxi-system.yaml`)

## Description
ESXi System login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/ui/#/login
```

