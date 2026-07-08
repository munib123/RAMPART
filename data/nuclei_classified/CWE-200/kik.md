# Vulnerability: Kik User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`kik.yaml`)

## Description
Kik user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ws2.kik.com/user/{{user}}
```

