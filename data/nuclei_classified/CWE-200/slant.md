# Vulnerability: Slant User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`slant.yaml`)

## Description
Slant user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.slant.co/users/{{user}}
```

