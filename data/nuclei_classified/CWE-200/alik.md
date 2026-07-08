# Vulnerability: Alik User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`alik.yaml`)

## Description
Alik user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.alik.cz/u/{{user}}
```

