# Vulnerability: Coroflot User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`coroflot.yaml`)

## Description
Coroflot user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.coroflot.com/{{user}}
```

