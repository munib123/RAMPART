# Vulnerability: Beszel Unfinished Installation
**Classification:** BESZEL
**Source:** Nuclei Template (`beszel-unfinished-installation.yaml`)

## Description
Detected Beszel server monitoring hub had an unfinished installation with no admin account configured, allowing attackers to create an admin account and gain full control.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/api/beszel/first-run
```

