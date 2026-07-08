# Vulnerability: Venmo User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`venmo.yaml`)

## Description
Venmo user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://account.venmo.com/u/{{user}}
```

