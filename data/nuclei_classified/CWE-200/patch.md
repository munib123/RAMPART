# Vulnerability: Patch User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`patch.yaml`)

## Description
Patch user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://patch.com/users/{{user}}
```

