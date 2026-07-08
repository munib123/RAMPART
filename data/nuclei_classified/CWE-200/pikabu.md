# Vulnerability: Pikabu User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pikabu.yaml`)

## Description
Pikabu user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://pikabu.ru/@{{user}}
```

