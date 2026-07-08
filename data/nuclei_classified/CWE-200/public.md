# Vulnerability: Public User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`public.yaml`)

## Description
Public user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://public.com/@{{user}}
```

