# Vulnerability: Depop User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`depop.yaml`)

## Description
Depop user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.depop.com/{{user}}/
```

