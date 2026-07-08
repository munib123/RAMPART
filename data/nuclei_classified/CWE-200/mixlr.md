# Vulnerability: Mixlr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mixlr.yaml`)

## Description
Mixlr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://api.mixlr.com/users/{{user}}
```

