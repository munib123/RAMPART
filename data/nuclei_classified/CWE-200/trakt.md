# Vulnerability: Trakt User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`trakt.yaml`)

## Description
Trakt user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://trakt.tv/users/{{user}}
```

