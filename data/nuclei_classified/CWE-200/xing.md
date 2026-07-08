# Vulnerability: Xing User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xing.yaml`)

## Description
Xing user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.xing.com/profile/{{user}}
```

