# Vulnerability: Somfy Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`somfy-login.yaml`)

## Description
Somfy login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/m_login.htm
```

