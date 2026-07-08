# Vulnerability: Patreon User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`patreon.yaml`)

## Description
Patreon user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.patreon.com/{{user}}
```

