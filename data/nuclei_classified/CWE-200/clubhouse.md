# Vulnerability: Clubhouse User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`clubhouse.yaml`)

## Description
Clubhouse user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.clubhouse.com/@{{user}}
```

