# Vulnerability: Pornhub Users User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pornhub-users.yaml`)

## Description
Pornhub Users user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.pornhub.com/users/{{user}}
```

