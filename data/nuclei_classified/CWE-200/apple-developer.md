# Vulnerability: Apple Developer User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apple-developer.yaml`)

## Description
Apple Developer user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://developer.apple.com/forums/profile/{{user}}
```

