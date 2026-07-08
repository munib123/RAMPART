# Vulnerability: Sourceforge User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`sourceforge.yaml`)

## Description
Sourceforge user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://sourceforge.net/u/{{user}}/profile
```

