# Vulnerability: Stripchat User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`stripchat.yaml`)

## Description
Stripchat user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://stripchat.com/{{user}}
```

