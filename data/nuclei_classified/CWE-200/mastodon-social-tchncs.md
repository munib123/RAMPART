# Vulnerability: Mastodon-social tchncs User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`mastodon-social-tchncs.yaml`)

## Description
Mastodon-social tchncs user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://social.tchncs.de/@{{user}}
```

