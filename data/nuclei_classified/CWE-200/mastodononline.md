# Vulnerability: Mastodon.online User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodononline.yaml`)

## Description
Mastodon.online user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://mastodon.online/@{{user}}
```

