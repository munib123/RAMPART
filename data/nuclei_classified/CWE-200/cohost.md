# Vulnerability: Cohost User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cohost.yaml`)

## Description
Cohost user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://cohost.org/{{user}}
```

