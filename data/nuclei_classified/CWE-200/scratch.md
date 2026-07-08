# Vulnerability: Scratch User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`scratch.yaml`)

## Description
Scratch user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://scratch.mit.edu/users/{{user}}/
```

