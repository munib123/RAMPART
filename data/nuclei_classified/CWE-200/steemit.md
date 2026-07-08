# Vulnerability: Steemit User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`steemit.yaml`)

## Description
Steemit user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://steemit.com/@{{user}}
```

