# Vulnerability: Patronite User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`patronite.yaml`)

## Description
Patronite user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://patronite.pl/{{user}}
```

