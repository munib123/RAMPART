# Vulnerability: Dojoverse User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`dojoverse.yaml`)

## Description
Dojoverse user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://dojoverse.com/members/{{user}}/
```

