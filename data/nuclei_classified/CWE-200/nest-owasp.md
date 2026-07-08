# Vulnerability: OWASP NEST User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`nest-owasp.yaml`)

## Description
OWASP NEST user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://nest.owasp.org/members/{{user}}
```

