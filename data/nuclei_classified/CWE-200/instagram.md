# Vulnerability: Instagram User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`instagram.yaml`)

## Description
Instagram user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.instagram.com/{{user}}
```

