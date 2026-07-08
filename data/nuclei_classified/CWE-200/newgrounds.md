# Vulnerability: Newgrounds User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`newgrounds.yaml`)

## Description
Newgrounds user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{user}}.newgrounds.com/
```

