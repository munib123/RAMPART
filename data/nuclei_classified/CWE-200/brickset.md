# Vulnerability: Brickset User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`brickset.yaml`)

## Description
Brickset user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://forum.brickset.com/profile/{{user}}
```

