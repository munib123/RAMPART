# Vulnerability: Gettr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gettr.yaml`)

## Description
Gettr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.gettr.com/s/user/{{user}}/exist
```

