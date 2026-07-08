# Vulnerability: Mintme User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mintme.yaml`)

## Description
Mintme user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.mintme.com/token/{{user}}
```

