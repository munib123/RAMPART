# Vulnerability: Cash.app User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cashapp.yaml`)

## Description
Cash.app user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cash.app/${{user}}
```

