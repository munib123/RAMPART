# Vulnerability: Bandlab User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bandlab.yaml`)

## Description
Bandlab user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.bandlab.com/api/v1.3/users/{{user}}
```

