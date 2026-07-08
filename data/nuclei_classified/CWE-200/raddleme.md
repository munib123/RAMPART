# Vulnerability: Raddle.me User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`raddleme.yaml`)

## Description
Raddle.me user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://raddle.me/user/{{user}}
```

