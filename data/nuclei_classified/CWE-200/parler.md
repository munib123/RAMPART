# Vulnerability: Parler User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`parler.yaml`)

## Description
Parler user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://parler.com/user/{{user}}
```

