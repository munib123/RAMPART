# Vulnerability: Boosty User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`boosty.yaml`)

## Description
Boosty user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://boosty.to/{{user}}
```

