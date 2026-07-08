# Vulnerability: 247sports User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`247sports.yaml`)

## Description
247sports user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://247sports.com/User/{{user}}/
```

