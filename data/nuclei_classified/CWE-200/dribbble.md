# Vulnerability: Dribbble User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dribbble.yaml`)

## Description
Dribbble user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://dribbble.com/{{user}}
```

