# Vulnerability: Graphics.social (Mastodon Instance) User Name Information - Detect
**Classification:** CWE-200
**Source:** Nuclei Template (`graphicssocial-mastodon-instance.yaml`)

## Description
Graphics.social (Mastodon Instance) user name information check was conducted.

## Vulnerable Code Pattern / Exploit Payload
```http
GET https://graphics.social/api/v1/accounts/lookup?acct={{user}}
```

