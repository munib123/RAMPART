# Vulnerability: Bandcamp User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bandcamp.yaml`)

## Description
Bandcamp user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://bandcamp.com/{{user}}
```

