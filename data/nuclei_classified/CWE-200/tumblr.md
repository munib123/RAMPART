# Vulnerability: Tumblr User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`tumblr.yaml`)

## Description
Tumblr user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://{{valid_username}}.tumblr.com
```

