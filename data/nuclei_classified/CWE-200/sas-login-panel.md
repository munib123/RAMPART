# Vulnerability: SAS Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sas-login-panel.yaml`)

## Description
SAS login panel has been detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/SASLogon/login
```

