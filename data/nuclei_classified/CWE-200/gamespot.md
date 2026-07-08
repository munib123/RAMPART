# Vulnerability: Gamespot User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`gamespot.yaml`)

## Description
Gamespot user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.gamespot.com/profile/{{user}}/
```

