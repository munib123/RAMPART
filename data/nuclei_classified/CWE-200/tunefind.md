# Vulnerability: Tunefind User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tunefind.yaml`)

## Description
Tunefind user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.tunefind.com/user/profile/{{user}}
```

