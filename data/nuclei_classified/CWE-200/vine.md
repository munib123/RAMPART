# Vulnerability: Vine User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vine.yaml`)

## Description
Vine user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vine.co/api/users/profiles/vanity/{{user}}
```

