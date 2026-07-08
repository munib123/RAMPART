# Vulnerability: Wykop User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wykop.yaml`)

## Description
Wykop user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.wykop.pl/ludzie/{{user}}/
```

