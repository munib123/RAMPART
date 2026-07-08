# Vulnerability: Last.fm User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`lastfm.yaml`)

## Description
Last.fm user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://last.fm/user/{{user}}
```

