# Vulnerability: Popl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`popl.yaml`)

## Description
Popl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://poplme.co/{{user}}
```

