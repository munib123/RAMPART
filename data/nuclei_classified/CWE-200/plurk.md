# Vulnerability: Plurk User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`plurk.yaml`)

## Description
Plurk user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.plurk.com/{{user}}
```

