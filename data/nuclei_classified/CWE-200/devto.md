# Vulnerability: Dev.to User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`devto.yaml`)

## Description
Dev.to user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://dev.to/{{user}}
```

