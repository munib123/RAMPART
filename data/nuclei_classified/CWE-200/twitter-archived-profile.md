# Vulnerability: Twitter archived profile User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`twitter-archived-profile.yaml`)

## Description
Twitter archived profile user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET http://archive.org/wayback/available?url=https://twitter.com/{{user}}
```

