# Vulnerability: Vampr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vampr.yaml`)

## Description
Vampr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.vampr.me/artist/{{user}}
```

