# Vulnerability: Wego User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`wego.yaml`)

## Description
Wego user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://wego.social/{{user}}
```

