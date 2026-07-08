# Vulnerability: HiveManager Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`hivemanager-login-panel.yaml`)

## Description
HiveManager login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/hm/login.action
```

