# Vulnerability: Watchmemore.com User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`watchmemorecom.yaml`)

## Description
Watchmemore.com user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.watchmemore.com/api3/profile/{{user}}/
```

