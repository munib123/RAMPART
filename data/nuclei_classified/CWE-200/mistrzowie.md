# Vulnerability: Mistrzowie User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mistrzowie.yaml`)

## Description
Mistrzowie user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mistrzowie.org/user/{{user}}
```

