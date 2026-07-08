# Vulnerability: Furiffic User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`furiffic.yaml`)

## Description
Furiffic user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.furiffic.com/{{user}}
```

