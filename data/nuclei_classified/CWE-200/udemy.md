# Vulnerability: Udemy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`udemy.yaml`)

## Description
Udemy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.udemy.com/user/{{user}}/
```

