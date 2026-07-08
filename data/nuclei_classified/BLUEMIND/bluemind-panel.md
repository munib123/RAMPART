# Vulnerability: Bluemind Panel - Detect
**Classification:** BLUEMIND
**Source:** Nuclei Template (`bluemind-panel.yaml`)

## Description
Bluemind application panel was discovered.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/native
```

