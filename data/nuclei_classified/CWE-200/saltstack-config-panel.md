# Vulnerability: SaltStack Config Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`saltstack-config-panel.yaml`)

## Description
SaltStack config panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login
```

