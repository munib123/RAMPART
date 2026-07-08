# Vulnerability: Meet me User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`meet-me.yaml`)

## Description
Meet me user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.meetme.com/{{user}}
```

