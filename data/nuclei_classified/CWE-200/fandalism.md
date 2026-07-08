# Vulnerability: Fandalism User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`fandalism.yaml`)

## Description
Fandalism user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://fandalism.com/{{user}}
```

