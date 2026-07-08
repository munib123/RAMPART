# Vulnerability: Picsart User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`picsart.yaml`)

## Description
Picsart user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://picsart.com/u/{{user}}
```

