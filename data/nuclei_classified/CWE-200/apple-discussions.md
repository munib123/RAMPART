# Vulnerability: Apple Discussions User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`apple-discussions.yaml`)

## Description
Apple Discussions user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://discussions.apple.com/profile/{{user}}
```

