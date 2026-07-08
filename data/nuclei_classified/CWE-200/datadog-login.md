# Vulnerability: Datadog Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`datadog-login.yaml`)

## Description
Datadog login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/account/login
```

