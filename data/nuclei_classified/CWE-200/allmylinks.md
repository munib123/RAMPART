# Vulnerability: Allmylinks User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`allmylinks.yaml`)

## Description
Allmylinks user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://allmylinks.com/{{user}}
```

