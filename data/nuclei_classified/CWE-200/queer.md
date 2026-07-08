# Vulnerability: QUEER User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`queer.yaml`)

## Description
QUEER user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://queer.pl/user/{{user}}
```

