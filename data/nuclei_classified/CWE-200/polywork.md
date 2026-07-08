# Vulnerability: Polywork User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`polywork.yaml`)

## Description
Polywork user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://polywork.com/{{user}}
```

