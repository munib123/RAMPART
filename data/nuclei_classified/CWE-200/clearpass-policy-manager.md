# Vulnerability: ClearPass Policy Manager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`clearpass-policy-manager.yaml`)

## Description
ClearPass Policy Manager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/tips/tipsLogin.action
```

