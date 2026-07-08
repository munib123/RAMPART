# Vulnerability: NPMjs User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`npmjs.yaml`)

## Description
NPMjs user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.npmjs.com/~{{user}}
```

