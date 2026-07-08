# Vulnerability: Taringa User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`taringa.yaml`)

## Description
Taringa user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.taringa.net/{{user}}
```

