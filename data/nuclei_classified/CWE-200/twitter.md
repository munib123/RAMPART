# Vulnerability: Twitter User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`twitter.yaml`)

## Description
Twitter user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://nitter.net/{{user}}
```

