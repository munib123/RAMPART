# Vulnerability: Carbonmade User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`carbonmade.yaml`)

## Description
Carbonmade user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.carbonmade.com/
```

