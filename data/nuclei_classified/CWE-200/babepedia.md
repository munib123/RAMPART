# Vulnerability: Babepedia User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`babepedia.yaml`)

## Description
Babepedia user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.babepedia.com/user/{{user}}
```

