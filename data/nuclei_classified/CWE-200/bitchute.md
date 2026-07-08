# Vulnerability: Bitchute User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`bitchute.yaml`)

## Description
Bitchute user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.bitchute.com/channel/{{user}}/
```

