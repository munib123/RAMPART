# Vulnerability: Behance User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`behance.yaml`)

## Description
Behance user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.behance.net/{{user}}
```

