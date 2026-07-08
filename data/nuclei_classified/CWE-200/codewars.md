# Vulnerability: Codewars User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`codewars.yaml`)

## Description
Codewars user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.codewars.com/users/{{user}}
```

