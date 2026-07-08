# Vulnerability: Twpro User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`twpro.yaml`)

## Description
Twpro user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://twpro.jp/{{user}}
```

