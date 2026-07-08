# Vulnerability: FortiAuthenticator - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fortiauthenticator-detect.yaml`)

## Description
The FortiAuthenticator panel was detected.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/v1
```

