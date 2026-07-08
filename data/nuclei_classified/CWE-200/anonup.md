# Vulnerability: Anonup User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`anonup.yaml`)

## Description
Anonup user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://anonup.com/@{{user}}
```

