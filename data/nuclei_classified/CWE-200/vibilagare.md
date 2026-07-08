# Vulnerability: Vibilagare User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vibilagare.yaml`)

## Description
Vibilagare user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.vibilagare.se/users/{{user}}
```

