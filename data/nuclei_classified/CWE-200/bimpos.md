# Vulnerability: Bimpos User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bimpos.yaml`)

## Description
Bimpos user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ask.bimpos.com/user/{{user}}
```

