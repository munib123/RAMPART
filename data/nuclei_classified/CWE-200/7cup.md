# Vulnerability: 7cup User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`7cup.yaml`)

## Description
7cup user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.7cups.com/@{{user}}
```

