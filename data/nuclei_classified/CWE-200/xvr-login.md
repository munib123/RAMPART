# Vulnerability: XVR Login Panel - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xvr-login.yaml`)

## Description
XVR login panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/login.rsp
```

