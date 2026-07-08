# Vulnerability: REDGIFS User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`redgifs.yaml`)

## Description
REDGIFS user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.redgifs.com/v1/users/{{user}}
```

