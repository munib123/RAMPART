# Vulnerability: IsMyGirl User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`ismygirl.yaml`)

## Description
IsMyGirl user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://api.fxcservices.com/pub/user/{{user}}
```

