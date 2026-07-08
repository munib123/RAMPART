# Vulnerability: Keybase User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`keybase.yaml`)

## Description
Keybase user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://keybase.io/{{user}}
```

