# Vulnerability: Pillowfort User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`pillowfort.yaml`)

## Description
Pillowfort user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.pillowfort.social/{{user}}
```

