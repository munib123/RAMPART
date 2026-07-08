# Vulnerability: Fansly User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fansly.yaml`)

## Description
Fansly user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://apiv2.fansly.com/api/v1/account?usernames={{user}}
```

