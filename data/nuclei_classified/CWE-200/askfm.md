# Vulnerability: Ask.fm User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`askfm.yaml`)

## Description
Ask.fm user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://ask.fm/{{user}}
```

