# Vulnerability: Giphy User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`giphy.yaml`)

## Description
Giphy user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://giphy.com/channel/{{user}}
```

