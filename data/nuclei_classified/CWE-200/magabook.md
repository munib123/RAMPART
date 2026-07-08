# Vulnerability: MAGABOOK User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`magabook.yaml`)

## Description
MAGABOOK user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://magabook.com/{{user}}
```

