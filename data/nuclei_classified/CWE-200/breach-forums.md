# Vulnerability: Breach Forums User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`breach-forums.yaml`)

## Description
Breach Forums user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://breached.vc/User-{{user}}
```

