# Vulnerability: Redbubble User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`redbubble.yaml`)

## Description
Redbubble user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://www.redbubble.com/people/{{user}}/shop
```

