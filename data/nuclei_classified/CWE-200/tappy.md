# Vulnerability: Tappy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tappy.yaml`)

## Description
Tappy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.tappy.tech/api/profile/username/{{user}}
```

