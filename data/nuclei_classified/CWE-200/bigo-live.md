# Vulnerability: BIGO Live User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bigo-live.yaml`)

## Description
BIGO Live user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.bigo.tv/user/{{user}}
```

