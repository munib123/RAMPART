# Vulnerability: Allied Telesis Device GUI Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`allied-telesis-exposure.yaml`)

## Description
Allied Telesis Device GUI login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/public/login.html
```

