# Vulnerability: Medium User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`medium.yaml`)

## Description
Medium user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://medium.com/@{{user}}
```

