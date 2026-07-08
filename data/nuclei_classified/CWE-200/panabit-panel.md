# Vulnerability: Panabit Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`panabit-panel.yaml`)

## Description
Panabit login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login/login.htm
```

