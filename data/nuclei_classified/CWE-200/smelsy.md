# Vulnerability: Smelsy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`smelsy.yaml`)

## Description
Smelsy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.smelsy.com/profile/{{user}}
```

