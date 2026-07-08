# Vulnerability: Cameo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`cameo.yaml`)

## Description
Cameo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.cameo.com/{{user}}
```

