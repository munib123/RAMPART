# Vulnerability: Thetattooforum User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`thetattooforum.yaml`)

## Description
Thetattooforum user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.thetattooforum.com/members/{{user}}/
```

