# Vulnerability: Producthunt User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`producthunt.yaml`)

## Description
Producthunt user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.producthunt.com/@{{user}}
```

