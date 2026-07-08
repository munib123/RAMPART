# Vulnerability: Flipboard User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`flipboard.yaml`)

## Description
Flipboard user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://flipboard.com/@{{user}}
```

