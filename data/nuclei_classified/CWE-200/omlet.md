# Vulnerability: Omlet User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`omlet.yaml`)

## Description
Omlet user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://omlet.gg/profile/{{user}}
```

