# Vulnerability: Blogspot User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`blogspot.yaml`)

## Description
Blogspot user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{user}}.blogspot.com
```

