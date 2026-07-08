# Vulnerability: AllTrails User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`alltrails.yaml`)

## Description
AllTrails user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.alltrails.com/members/{{user}}
```

