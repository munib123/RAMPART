# Vulnerability: Revolut User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`revolut.yaml`)

## Description
Revolut user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://revolut.me/api/web-profile/{{user}}
```

