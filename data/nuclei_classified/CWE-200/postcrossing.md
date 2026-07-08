# Vulnerability: Postcrossing User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`postcrossing.yaml`)

## Description
Postcrossing user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.postcrossing.com/user/{{user}}
```

