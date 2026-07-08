# Vulnerability: Letterboxd User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`letterboxd.yaml`)

## Description
Letterboxd user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://letterboxd.com/{{user}}/
```

