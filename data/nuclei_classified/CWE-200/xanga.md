# Vulnerability: Xanga User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`xanga.yaml`)

## Description
Xanga user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://{{user}}.xanga.com/
```

