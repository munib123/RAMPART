# Vulnerability: Giters User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`giters.yaml`)

## Description
Giters user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://giters.com/{{user}}
```

