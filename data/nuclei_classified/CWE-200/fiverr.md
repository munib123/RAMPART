# Vulnerability: Fiverr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fiverr.yaml`)

## Description
Fiverr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.fiverr.com/{{user}}
```

