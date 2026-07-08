# Vulnerability: Vero User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vero.yaml`)

## Description
Vero user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://vero.co/{{user}}
```

