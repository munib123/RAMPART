# Vulnerability: Vivino User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`vivino.yaml`)

## Description
Vivino user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.vivino.com/users/{{user}}
```

